import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  HttpException,
  HttpStatus,
  Inject,
  Logger,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { CreateUserDto } from '../user/dtos/createUser.dto';
import { PublicUserDetails, UserId } from '../user/interfaces/user.interface';
import { UserRepository } from '../user/repository/user.repository';
import { Status,RegisterType } from '../user/types/user.types';
import { LoginUserDto } from '../user/dtos/loginUser.dto';
import { ConfigService } from '@nestjs/config';
import { HttpService } from '@nestjs/axios';
import { JwtService } from '@nestjs/jwt';
import { EmailService } from '../email/email.service';
import { CreateGoogleUserDto } from '../user/dtos/createGoogleUser.dto';
import { UpdateUserPasswordDto } from '../user/dtos/updateUserPasssword.dto';
import { CreateNewPasswordDto } from '../user/dtos/createNewPassword.dto';
import { ForgotPasswordDto } from '../user/dtos/forgotPassword.dto';
import { ResetPasswordDto } from '../user/dtos/resetPassword.dto';
import { UpdateUserInfoDto } from '../user/dtos/updateUserInfo.dto';
import { RedisClient } from '../redis/redis.provider';
import * as address from 'address';
import { VerifyCodeDto } from 'src/user/dtos/verifyCode.dto';
const ip:any = address.ip();

@Injectable()
export class AuthService {
  private readonly logger = new Logger(`${ip} src/auth/auth.service.ts`);

  constructor(
    private userRepository: UserRepository,
    private readonly httpService: HttpService,
    private jwtService: JwtService,
    private emailService: EmailService,
    private configService: ConfigService,
    @Inject('REDIS_CLIENT')
    private readonly redis: RedisClient,
  ) {}

  // Sign up
  async signUp(
    createUserDto: CreateUserDto,
  ): Promise<{ access_token: string; mail_access_token: string }> {
    const {
      first_name,
      last_name,
      email,
      password,
    } = createUserDto;

    // Validate Password
    const isPasswordValid = this.userRepository._validatePassword(password);

    const passwordSuccess = isPasswordValid.success;
    const passwordMessage = isPasswordValid.message;

    if (!passwordSuccess) {
      this.logger.warn({ success: passwordSuccess, message: passwordMessage });
      throw new HttpException(
        { success: passwordSuccess, message: passwordMessage },
        HttpStatus.BAD_REQUEST,
      );
    }

    // Checking if there is a user with the provided email address
    const existingEmailUser = await this.userRepository.findByEmail(email);
    if (existingEmailUser) {
      const { register_type } = existingEmailUser;

      if (register_type === RegisterType.GOOGLE) {
        this.logger.warn(
          'This email address has already been used to sign up using Google. Please sign in with your Google account or use a different email address to register.',
        );
        throw new ConflictException(
          'This email address has already been used to sign up using Google. Please sign in with your Google account or use a different email address to register.',
        );
      }
      this.logger.warn(
        'This email address is already in use. Please use a different email or sign in with your existing account.',
      );
      throw new ConflictException(
        'This email address is already in use. Please use a different email or sign in with your existing account.',
      );
    }

    // Hashing the password
    const hashedPassword = await this.userRepository._hashPassword(password);

    // Generate a verification code for user validations
    const verificationCode = this.userRepository._verificationCodeGenerate(6);

    // User create in the DB
    const newUser = await this.userRepository.createUser(
      {
        first_name,
        last_name,
        email,
        password: hashedPassword,
        verification_code: verificationCode,
      }
    );


    // Get the user Id
    const userId = this.userRepository._getUserId(newUser.id);

    // Generate a access token using user id
    const jwt = await this.jwtService.signAsync({ type: 'access', userId });

    // Generate a access token using user id for verification mail
    const mail_jwt = await this.jwtService.signAsync({
      type: 'verification',
      userId,
    });
    // User email verification
    await this.emailService.sendVerificationEmail(
      { first_name, last_name, email, verification_code: verificationCode },
      mail_jwt,
    );

    return {
      access_token: jwt,
      mail_access_token: mail_jwt,
    };
  }

  // Email verification
  async userEmailVerificationByLink(
    access_token: string,
    verification_code: number,
  ): Promise<{ access_token: string; isVerified: boolean }> {
    const isMember = await this.redis.sismember(
      'whitelisted_access_tokens',
      access_token,
    );

    if (isMember == 0) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }
    // Decode the provided access token
    const decodedJWT = await this.userRepository._decodeJWT(access_token);
  // Checking the decoded jwt
  if (!decodedJWT.userId && !decodedJWT.userId.id) {
    this.logger.warn('Invalid access token.');
    throw new UnauthorizedException('Invalid access token.');
  }

    // Checking is there a user with is user id
    const validateUser = await this.userRepository.findById(
      decodedJWT.userId.id,
    );

    if (!validateUser) {
      this.logger.warn(
        `We couldn't find any user associated with that access token.`,
      );
      throw new UnauthorizedException(
        `We couldn't find any user associated with that access token.`,
      );
    }
    // Generate new verification code before verify the user
    const newVerificationCode =
      this.userRepository._verificationCodeGenerate(6);

    // Create a new jwt access token
    const newJwt = await this.jwtService.signAsync({
      userId: { id: decodedJWT.userId.id },
    });
    console.log(verification_code,validateUser.verification_code)
    // Checking the request verificationCode with db verification code
    if (Number(verification_code) !== Number(validateUser.verification_code)) {
      this.logger.warn(`The verification code you provided is not valid.`);
      throw new UnauthorizedException(
        'The verification code you provided is not valid.',
      );
    }

    

    if (
      validateUser.pending_email
    ) {
      // Update the user with new verification for another use case
      await this.userRepository.updateById(validateUser.id, {
        is_verified: true,
        verification_code: Number(verification_code),
        status: Status.ACTIVE,
        email: validateUser.pending_email,
        pending_email: null,
      });

      // await this.userRepository.updateLastActiveDate(validateUser.id);
    } else {
      // Update the user with new verification for another use case
      await this.userRepository.updateById(validateUser.id, {
        is_verified: true,
        verification_code: Number(verification_code),
        status: Status.ACTIVE,
      });

      // await this.userRepository.updateLastActiveDate(validateUser.id);
    }

    return { access_token: newJwt, isVerified: true };
  }

  // Resend email verification
  async resendVerification(
    access_token: string,
  ): Promise<{ access_token: string }> {
    const isMember = await this.redis.sismember(
      'whitelisted_access_tokens',
      access_token,
    );

    if (isMember == 0) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }
    // Decode the provided access token
    const decodedJWT = await this.userRepository._decodeJWT(access_token);
    // Check decoded token states validation
    if (!decodedJWT.userId && !decodedJWT.userId.id) {
      this.logger.warn(`Invalid access token.`);
      throw new UnauthorizedException('Invalid access token.');
    }

    // Check existing user validation by the id
    const validateUser = await this.userRepository.findById(
      decodedJWT.userId.id,
    );

    if (!validateUser) {
      this.logger.warn(
        `Invalid access token. The token you provided does not match any account in our system.`,
      );
      throw new UnauthorizedException(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
    }
    // re-generate the verification code
    const newVerificationCode =
      this.userRepository._verificationCodeGenerate(6);

    // Update the re-generated code in user
    const updatedUser = await this.userRepository.updateById(validateUser.id, {
      verification_code: newVerificationCode,
    });

    const {
      id,
      first_name,
      last_name,
      email,
      verification_code,
      pending_email,
    } = updatedUser;

    // Get the updated user id from the db
    const userId = this.userRepository._getUserId(id);

    // Create new access token form the user id
    const jwt = await this.jwtService.signAsync({ userId });

    // Create a new jwt access token
    const newJwt = await this.jwtService.signAsync({
      userId: { id: decodedJWT.userId.id },
    });

    // Making sending email
    let sending_email =
      pending_email  ? pending_email : email;

    // Send the resend verification email
    await this.emailService.sendVerificationEmail(
      { first_name, last_name, email: sending_email, verification_code },
      jwt,
    );

    return { access_token: newJwt };
  }

  async signIn(loginUserDto: LoginUserDto): Promise<{ access_token: string }> {
    const { email, password } = loginUserDto;

    // Validate Password
    const isPasswordValid = this.userRepository._validatePassword(password);

    const passwordSuccess = isPasswordValid.success;
    const passwordMessage = 'Invalid username or password.';

    if (!passwordSuccess) {
      this.logger.warn({ success: passwordSuccess, message: passwordMessage });
      throw new HttpException(
        { success: passwordSuccess, message: passwordMessage },
        HttpStatus.BAD_REQUEST,
      );
    }

    // Validate user
    const userId = await this._validateUser(email, password);

    if (!userId) {
      this.logger.warn(
        'It seems like your login credentials are incorrect. Please double-check and try again.',
      );
      throw new UnauthorizedException(
        'It seems like your login credentials are incorrect. Please double-check and try again.',
      );
    }


    // Create new access token for the loging user
    const jwt = await this.jwtService.signAsync({ userId });

    return { access_token: jwt };
  }

  async createGoogleUser(createGoogleUserDto: CreateGoogleUserDto): Promise<{
    success: boolean;
    access_token: string;
    message: string;
    path: string | null;
  }> {
    const { email } = createGoogleUserDto;

    // Check if email is already registered
    const existingUser = await this.userRepository.findByEmail(email);

    // Do this if there is no any user with this email
    if (!existingUser) {
      const { id } = await this.userRepository.createGoogleUser(
        createGoogleUserDto,
      );


      // Create access token
      const jwt = await this.jwtService.signAsync({ userId: { id } });
      return {
        success: true,
        access_token: jwt,
        message: 'You have successfully signed up with your Google account.',
        path: 'profile',
      };

      // Do this if there is a user with this email
    } else {
      const { register_type, status } = existingUser;

      if (register_type === RegisterType.MANUAL) {
        return {
          success: false,
          access_token: null,
          message:
            'You need to log in manually as you have been signed up manually.',
          path: 'signup',
        };
      }

      if (status === Status.DEACTIVATED) {
        return {
          success: false,
          access_token: null,
          message:
            'Your account has been deactivated. Please contact our support team for further assistance.',
          path: 'signup',
        };
      }

      if (status === Status.BANNED) {
        return {
          success: false,
          access_token: null,
          message:
            'Your account has been banned. Please contact our support team for further assistance.',
          path: 'signup',
        };
      }

      // If google user exist, update deatils with new details
      const { id } = await this.userRepository.updateGoogleUserById(
        existingUser.id,
        createGoogleUserDto,
      );

      // Create access_token google user access_token
      const jwt = await this.jwtService.signAsync({ userId: { id: id } });
      return {
        success: true,
        access_token: jwt,
        message: 'Google user successfully authenticated.',
        path: 'profile',
      };
    }
  }

  async deactivateUser(access_token: string) {
    const isMember = await this.redis.sismember(
      'whitelisted_access_tokens',
      access_token,
    );

    if (isMember == 0) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }
    // Decode access_token
    let decodedJwt = await this.userRepository._decodeJWT(access_token);

    // Validate decoded token
    if (!decodedJwt.userId && !decodedJwt.userId.id) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }

    // Check if there is a user
    const user = await this.userRepository.findById(decodedJwt.userId.id);

    if (!user) {
      this.logger.warn(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
      throw new UnauthorizedException(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
    }

    if (user.status === Status.DEACTIVATED) {
      return {
        success: false,
        message: 'Your account has already been deactivated.',
      };
    }

    const deactivatedUser = await this.userRepository.updateById(
      decodedJwt.userId.id,
      {
        status: Status.DEACTIVATED,
      },
    );

    if (deactivatedUser) {
      const { first_name, last_name, email } = user;

      // Send deactivation email to user email
      await this.emailService.userDeactivateEmail({
        first_name,
        last_name,
        email,
      });

      return {
        success: true,
        message:
          'You have successfully deactivated your account. We hope to see you again soon.',
      };
    }
  }

  async getUserDetails(access_token: string): Promise<PublicUserDetails> {
    // Decode user token
    let decodedJwt = await this.userRepository._decodeJWT(access_token);

    // Validate jwt token
    if (!decodedJwt.UserId && !decodedJwt.userId.id) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }

    // Check if there is a user
    const user = await this.userRepository.findById(
      decodedJwt.userId.id,
    );

    if (!user) {
      this.logger.warn(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
      throw new UnauthorizedException(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
    }
    const { status } = user;

    if (status === Status.DEACTIVATED) {
      this.logger.warn(
        'Your account has been deactivated. Please contact our support team for further assistance.',
      );
      throw new UnauthorizedException(
        'Your account has been deactivated. Please contact our support team for further assistance.',
      );
    }
    if (status === Status.BANNED) {
      this.logger.warn(
        'Your account has been deactivated. Please contact our support team for further assistance.',
      );
      throw new UnauthorizedException(
        'Your account has been banned. Please contact our support team for further assistance.',
      );
    }
    return this.userRepository._getUserDetails(user);
  }

  async updateUserPassword(
    access_token: string,
    updateUserPasswordDto: UpdateUserPasswordDto,
  ): Promise<{ access_token: string }> {
    const isMember = await this.redis.sismember(
      'whitelisted_access_tokens',
      access_token,
    );

    if (isMember == 0) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }
    
    // Decode the provided access token
    const decodedJwt = await this.userRepository._decodeJWT(access_token);

    // Checking user
    if (!decodedJwt.userId && !decodedJwt.userId.id) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }

    // Get user
    const user = await this.userRepository.findById(decodedJwt.userId.id);

    if (!user) {
      this.logger.warn(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
      throw new UnauthorizedException(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
    }

    // Validate user
    const OldUserId = await this._validateUser(
      user.email,
      updateUserPasswordDto.currentPassword,
    );

    if (!OldUserId) {
      this.logger.warn(
        'The current password you entered is incorrect. Please try again.',
      );
      throw new UnauthorizedException(
        'The current password you entered is incorrect. Please try again.',
      );
    }

    // Validate Password
    const isPasswordValid = this.userRepository._validatePassword(
      updateUserPasswordDto.newPassword,
    );

    const passwordSuccess = isPasswordValid.success;
    const passwordMessage = isPasswordValid.message;

    if (!passwordSuccess) {
      this.logger.warn({ success: passwordSuccess, message: passwordMessage });
      throw new HttpException(
        { success: passwordSuccess, message: passwordMessage },
        HttpStatus.BAD_REQUEST,
      );
    }

    // Encrypt the provided password
    const hashedNewPassword = await this.userRepository._hashPassword(
      updateUserPasswordDto.newPassword,
    );

    // Update user with new hashed password
    const updatedUser = await this.userRepository.updatePasswordById(
      decodedJwt.userId.id,
      { password: hashedNewPassword },
    );

    // // Update last active date
    // await this.userRepository.updateLastActiveDate(updatedUser.id);

    // Get the updated user Id
    const userId = await this.userRepository._getUserId(updatedUser.id);

    // Create new jwt access_token for the user
    const jwt = await this.jwtService.signAsync({ userId });

    return { access_token: jwt };
  }

  async createNewPassword(
    access_token: string,
    createNewPasswordDto: CreateNewPasswordDto,
  ): Promise<{ access_token: string }> {

    const isMember = await this.redis.sismember(
      'whitelisted_access_tokens',
      access_token,
    );

    if (isMember == 0) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }
    // Decode the provided access token
    const decodedJwt = await this.userRepository._decodeJWT(access_token);

    // Checking user
    if (!decodedJwt.userId && !decodedJwt.userId.id) {

      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }

    // Get user
    const user = await this.userRepository.findById(decodedJwt.userId.id);

    if (!user) {
      this.logger.warn(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
      throw new UnauthorizedException(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
    }

    if (
      createNewPasswordDto.newPassword !== createNewPasswordDto.confirmPassword
    ) {
      this.logger.warn('Both passwords should be same.');
      throw new UnauthorizedException('Both passwords should be same.');
    }

    // Validate Password
    const isPasswordValid = this.userRepository._validatePassword(
      createNewPasswordDto.newPassword,
    );

    const passwordSuccess = isPasswordValid.success;
    const passwordMessage = isPasswordValid.message;

    if (!passwordSuccess) {
      this.logger.warn({ success: passwordSuccess, message: passwordMessage });
      throw new HttpException(
        { success: passwordSuccess, message: passwordMessage },
        HttpStatus.BAD_REQUEST,
      );
    }

    // Encrypt the provided password
    const hashedNewPassword = await this.userRepository._hashPassword(
      createNewPasswordDto.newPassword,
    );

    // Update user with new hashed password
    const updatedUser = await this.userRepository.updatePasswordById(
      decodedJwt.userId.id,
      { password: hashedNewPassword },
    );

    // // Update last active date
    // await this.userRepository.updateLastActiveDate(updatedUser.id);

    // Get the updated user Id
    const userId = await this.userRepository._getUserId(updatedUser.id);

    // Create new jwt access_token for the user
    const jwt = await this.jwtService.signAsync({ userId });

    return { access_token: jwt };
  }

  async forgotPasswordEmailHandle(forgotPasswordDto: ForgotPasswordDto) {
    // Check if there is user with that email
    const user = await this.userRepository.findByEmail(forgotPasswordDto.email);

    if (!user) {
      this.logger.warn(
        'Invalid email address. Please check the email you provided.',
      );
      return {
        success: true,
        message:
          'Password reset instructions have been sent. Confirm email address if no email received.',
      };
    }

    // Destructure user details
    const { id, first_name, last_name, email, status, register_type } = user;

    // Check user status
    if (register_type === RegisterType.GOOGLE) {
      this.logger.warn(
        'You need to use google login as you have been signed up using google authentication.',
      );
      return {
        success: true,
        message:
          'Password reset instructions have been sent. Confirm email address if no email received.',
      };
    }

    if (status === Status.DEACTIVATED) {
      this.logger.warn(
        'Your account has been deactivated. Please contact our support team for further assistance.',
      );
      return {
        success: true,
        message:
          'Password reset instructions have been sent. Confirm email address if no email received.',
      };
    }

    if (status === Status.BANNED) {
      this.logger.warn(
        'Your account has been deactivated. Please contact our support team for further assistance.',
      );
      return {
        success: true,
        message:
          'Password reset instructions have been sent. Confirm email address if no email received.',
      };
    }

    // Generate a new verification code
    const newVerificationCode =
      this.userRepository._verificationCodeGenerate(6);

    // Get updated verification code
    const { verification_code } = await this.userRepository.updateById(id, {
      verification_code: newVerificationCode,
    });

    const userId = this.userRepository._getUserId(id);

    // Jwt token
    const jwt = await this.jwtService.signAsync({ userId });

    // Send forgot password email
    await this.emailService.sendForgotPasswordEmail(
      { first_name, last_name, email, verification_code },
      jwt,
    );

    return { access_token: jwt };
  }
  async resetPasswordEmailHandle(forgotPasswordDto: ForgotPasswordDto) {
    
    // Check if there is user with that email
    const user = await this.userRepository.findByEmail(forgotPasswordDto.email);
    
    if (!user) {
      this.logger.warn(
        'Invalid email address. Please check the email you provided.',
      );
      return {
        success: true,
        message:
          'Password reset instructions have been sent. Confirm email address if no email received.',
      };
    }

    // Destructure user details
    const { id, first_name, last_name, email, status, register_type } = user;

    // Check user status
    if (register_type === RegisterType.GOOGLE) {
      this.logger.warn(
        'You need to use google login as you have been signed up using google authentication.',
      );
      return {
        success: true,
        message:
          'Password reset instructions have been sent. Confirm email address if no email received.',
      };
    }

    if (status === Status.DEACTIVATED) {
      this.logger.warn(
        'Your account has been deactivated. Please contact our support team for further assistance.',
      );
      return {
        success: true,
        message:
          'Password reset instructions have been sent. Confirm email address if no email received.',
      };
    }

    if (status === Status.BANNED) {
      this.logger.warn(
        'Your account has been deactivated. Please contact our support team for further assistance.',
      );
      return {
        success: true,
        message:
          'Password reset instructions have been sent. Confirm email address if no email received.',
      };
    }

    // Generate a new verification code
    const newVerificationCode =
      this.userRepository._verificationCodeGenerate(6);

    // Get updated verification code
    const { verification_code } = await this.userRepository.updateById(id, {
      verification_code: newVerificationCode,
    });

    const userId = this.userRepository._getUserId(id);

    // Jwt token
    const jwt = await this.jwtService.signAsync({ userId });

    // Send reset password email
    await this.emailService.sendResetPasswordEmail(
      { first_name, last_name, email, verification_code },
      jwt,
    );

    return { access_token: jwt };
  }

  async resetPassword(
    access_token: string,
    resetPasswordDto: ResetPasswordDto,
  ): Promise<{ access_token: string }> {

    const isMember = await this.redis.sismember(
      'whitelisted_access_tokens',
      access_token,
    );

    if (isMember == 0) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }
    // Decode the provided access token
    const decodedJwt = await this.userRepository._decodeJWT(access_token);

    // Checking user
    if (!decodedJwt.userId && !decodedJwt.userId.id) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }

    // Get user
    const user = await this.userRepository.findById(decodedJwt.userId.id);

    if (!user) {
      this.logger.warn(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
      throw new UnauthorizedException(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
    }

    // Checking the request verificationCode with db verification code
    if (
      Number(resetPasswordDto.verification_code) !==
      Number(user.verification_code)
    ) {
      this.logger.warn('The verification code you provided is not valid.');
      throw new UnauthorizedException(
        'The verification code you provided is not valid.',
      );
    }

    // Validate Password
    const isPasswordValid = this.userRepository._validatePassword(
      resetPasswordDto.newPassword,
    );

    const passwordSuccess = isPasswordValid.success;
    const passwordMessage = isPasswordValid.message;

    if (!passwordSuccess) {
      this.logger.warn({ success: passwordSuccess, message: passwordMessage });
      throw new HttpException(
        { success: passwordSuccess, message: passwordMessage },
        HttpStatus.BAD_REQUEST,
      );
    }

    // Generate new verification code before verify the user
    const newVerificationCode =
      this.userRepository._verificationCodeGenerate(6);

    // Encrypt the password to hash value
    const hashedPassword = await this.userRepository._hashPassword(
      resetPasswordDto.newPassword,
    );

    const updatedUser = await this.userRepository.updatePasswordById(
      decodedJwt.userId.id,
      { password: hashedPassword, verification_code: newVerificationCode },
    );

    // // Update last active date
    // await this.userRepository.updateLastActiveDate(updatedUser.id);

    // Get updated user id
    const userId = this.userRepository._getUserId(updatedUser.id);

    // Create jwt access_token
    const jwt = await this.jwtService.signAsync({ userId });

    return { access_token };
  }

  async verifyCode(
    access_token: string,
    verifyCodeDto: VerifyCodeDto,
  ): Promise<{ access_token: string }> {

    const isMember = await this.redis.sismember(
      'whitelisted_access_tokens',
      access_token,
    );

    if (isMember == 0) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }
    // Decode the provided access token
    const decodedJwt = await this.userRepository._decodeJWT(access_token);

    // Checking user
    if (!decodedJwt.userId && !decodedJwt.userId.id) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }

    // Get user
    const user = await this.userRepository.findById(decodedJwt.userId.id);

    if (!user) {
      this.logger.warn(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
      throw new UnauthorizedException(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
    }

    // Checking the request verificationCode with db verification code
    if (
      Number(verifyCodeDto.verification_code) !==
      Number(user.verification_code)
    ) {
      this.logger.warn('The verification code you provided is not valid.');
      throw new UnauthorizedException(
        'The verification code you provided is not valid.',
      );
    }
    // Destructure user details
    const { id, first_name, last_name, email, status, register_type,verification_code } = user;
    
    const userId = this.userRepository._getUserId(id);

    // Jwt token
    // const jwt = await this.jwtService.signAsync({ userId });
    // Send forgot password email
    await this.emailService.sendForgotPasswordEmail(
      { first_name, last_name, email, verification_code },
      access_token,
    );

    return { access_token };
  }

  async updateUserInfo(
    access_token: string,
    updateUserInfoDto: UpdateUserInfoDto,
  ): Promise<{ access_token: string }> {
    const isMember = await this.redis.sismember(
      'whitelisted_access_tokens',
      access_token,
    );

    if (isMember == 0) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }
    
    // Decode the provided access token
    const decodedJwt = await this.userRepository._decodeJWT(access_token);

    // Checking user
    if (!decodedJwt.userId && !decodedJwt.userId.id) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }

    // Checking the existing user with the user id
    const user = await this.userRepository.findById(decodedJwt.userId.id);

    if (!user) {
      this.logger.warn(
        `We couldn't find any user associated with that access token.`,
      );
      throw new UnauthorizedException(
        `We couldn't find any user associated with that access token.`,
      );
    }


    // Update only the properties that are provided in the DTO
    if (updateUserInfoDto.first_name) {
      user.first_name = updateUserInfoDto.first_name;
    }
    if (updateUserInfoDto.last_name) {
      user.last_name = updateUserInfoDto.last_name;
    }
    if (updateUserInfoDto.username) {
      user.username = updateUserInfoDto.username;
    }
    if (updateUserInfoDto.phone) {
      user.phone = updateUserInfoDto.phone;
    }
    if (updateUserInfoDto.experience) {
      user.experience = updateUserInfoDto.experience;
    }
    if (updateUserInfoDto.description) {
      user.description = updateUserInfoDto.description;
    }
    const existingEmailUser = await this.userRepository.findByEmail(updateUserInfoDto.email);
    if (updateUserInfoDto.email) {

      // if (existingEmailUser) {
      //   throw new ConflictException(
      //     'This email address is already in use. Please use a different email.',
      //   );
      // }
      user.pending_email = updateUserInfoDto.email;
    }
    
    // Generate a verification code for user validations
    const verificationCode = this.userRepository._verificationCodeGenerate(6);

    // Asign it to user
    user.verification_code = verificationCode;

    // Update user
    const updatedUser = await this.userRepository.updateById(
      decodedJwt.userId.id,
      user,
    );
    // Get userId
    const userId = this.userRepository._getUserId(updatedUser.id);

    // Create Jwt
    const jwt = await this.jwtService.signAsync({ userId });

    if (!existingEmailUser && updateUserInfoDto.email) {
      // User email verification
      await this.emailService.sendVerificationEmail(
        {
          first_name: updatedUser.first_name,
          last_name: updatedUser.last_name,
          email: updatedUser.pending_email,
          verification_code: updatedUser.verification_code,
        },
        jwt,
      );
    }

    return { access_token: jwt };
  }

 
  async _validateUser(email: string, password: string): Promise<UserId> {
    // Checking if there is a user
    const user = await this.userRepository.findByEmail(email);

    if (!user) {
      this.logger.warn('Invalid username or password.');
      throw new UnauthorizedException('Invalid username or password.');
    }

    const { register_type, status } = user;

    // Checking register_type
    if (register_type === RegisterType.GOOGLE) {
      this.logger.warn('Please use google login.');
      throw new UnauthorizedException('Please use google login.');
    }

    // If user banned
    if (status === Status.BANNED) {
      this.logger.warn('Access denied. Your account has been banned.');
      throw new UnauthorizedException(
        'Access denied. Your account has been banned.',
      );
    }

    // If user deactivated
    if (status === Status.DEACTIVATED) {
      this.logger.warn(
        'Your account has been deactivated. Please contact our support team for further assistance.',
      );
      throw new UnauthorizedException(
        'Your account has been deactivated. Please contact our support team for further assistance.',
      );
    }

    // Check password
    const doesPasswordMatch = await this.userRepository._doesPasswordMatch(
      password,
      user.password,
    );

    if (!doesPasswordMatch) {
      this.logger.warn('Invalid username or password.');
      throw new UnauthorizedException('Invalid username or password.');
    }

    // Get userId
    return this.userRepository._getUserId(user.id);
  }

  async updateLastActiveDate(access_token: string): Promise<void> {

    
    // Decode the provided access token
    const decodedJwt = await this.userRepository._decodeJWT(access_token);

    // Validate jwt token
    if (!decodedJwt.UserId && !decodedJwt.userId.id) {
      throw new UnauthorizedException('Invalid access token.');
    }

    // Check if there is a user
    const user = await this.userRepository.findById(decodedJwt.userId.id);

    if (!user) {
      throw new UnauthorizedException(
        'Invalid access token. The token you provided does not match any account in our system.',
      );
    }

  }

  async verifyGoogleRecaptcha(google_recaptcha_token) {
    try {
      const response = await this.httpService.axiosRef.post(
        `https://www.google.com/recaptcha/api/siteverify?secret=${this.configService.get(
          'GOOGLE_REPATCHA_SECRET_KEY',
        )}&response=${google_recaptcha_token}`,
      );

      return response.data;
    } catch (err) {
      return { success: false, error: err };
    }
  }
}
