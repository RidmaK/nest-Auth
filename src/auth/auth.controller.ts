import {
  Body,
  Req,
  Controller,
  Post,
  Get,
  HttpStatus,
  UnauthorizedException,
  BadGatewayException,
  Logger,
} from '@nestjs/common';
import {
  PublicUserDetails,
  UserAuthResponse,
} from '../user/interfaces/user.interface';
import { HttpCode, Inject, Put, Query, Res, Session, UploadedFile, UploadedFiles, UseGuards, UseInterceptors } from '@nestjs/common/decorators';
import { CreateUserDto } from '../user/dtos/createUser.dto';
import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { User } from '../user/entity/user.entity';
import { FileInterceptor } from '@nestjs/platform-express';
import { Express, Request, Response } from 'express';
import { LoginUserDto } from 'src/user/dtos/loginUser.dto';
import { UpdateUserInfoDto } from 'src/user/dtos/updateUserInfo.dto';
import { JwtCookieGuard } from './utils/jwtcookie.guard';
import { JwtGuard } from './utils/jwt.guard';
import { ResetPasswordDto } from 'src/user/dtos/resetPassword.dto';
import { VerifyCodeDto } from 'src/user/dtos/verifyCode.dto';
import { v4 as uuidv4 } from 'uuid';
import { GoogleAuthGuard } from './utils/google.guard';
import { UpdateUserPasswordDto } from 'src/user/dtos/updateUserPasssword.dto';
import { CreateNewPasswordDto } from 'src/user/dtos/createNewPassword.dto';
import { ForgotPasswordDto } from 'src/user/dtos/forgotPassword.dto';
import { RedisClient } from '../redis/redis.provider';
import * as address from 'address';
const ip:any = address.ip();
@Controller('auth')
export class AuthController {
  private readonly logger = new Logger(`${ip} src/auth/auth.controller.ts`);
  constructor(
    private authService: AuthService,
    private readonly configService: ConfigService,
    // @InjectRedis() private readonly redis: Redis,
    @Inject('REDIS_CLIENT')
    private readonly redis: RedisClient,
  ) {}

  @Post('/signup')
  // @Throttle(5, 60)
  async signUp(
    @Body() createUserDto: CreateUserDto,
    @Session() session: Record<string, any>,
    @Res({ passthrough: true }) res: Response,
  ): Promise<UserAuthResponse> {
    const { access_token, mail_access_token } = await this.authService.signUp(
      createUserDto,
    );

    session.session_token = uuidv4();

    await this.redis.sadd('whitelisted_access_tokens', access_token);
    await this.redis.sadd('whitelisted_access_tokens', mail_access_token);
    // session.session_token = uuidv4();
    // Add access_token to cookies
    res.cookie('access_token', access_token, {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });

    return {
      success: true,
      message: 'Successfully signed up!',
    };
  }

  @Get('/verification')
  @HttpCode(HttpStatus.OK)
  async userVerifiyByLink(
    @Res({ passthrough: true }) res: Response,
    @Query() query,
  ): Promise<UserAuthResponse> {
    console.log(query)
    // Checking access_token exist in query
    if (!query.access_token) {
      throw new UnauthorizedException(
        'You are not authorized to access this resource without a valid access token.',
      );
    }

    // Checking verification_code exist in query
    if (!query.verification_code) {
      throw new UnauthorizedException(
        'You are not authorized to verify your account without a valid verification code.',
      );
    }

    // Verifying user
    const verifiedUser = await this.authService.userEmailVerificationByLink(
      query.access_token,
      Number(query.verification_code),
    );

    if (!verifiedUser.isVerified)
      throw new BadGatewayException(
        'Your email is not verified. Please verify your email and try again later.',
      );

    
    this.redis.sadd('whitelisted_access_tokens', verifiedUser.access_token);

    res.cookie('access_token', verifiedUser.access_token, {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });

    return {
      success: true,
      message: 'Congratulations! Your account has been successfully verified.',
    };
  }

  @Get('/resend-verification')
  // @Throttle(5, 60)
  @HttpCode(HttpStatus.OK)
  async resendVerification(@Req() req: Request): Promise<UserAuthResponse> {
    // Remove Bearer part
    const access_token = req.headers.authorization.replace('Bearer ', '');

    // Checking the access token availability
    if (!access_token)
      throw new UnauthorizedException('Unauthorized access detected.');

    // Send the email with confirmation mail service
    const newAccessToken = await this.authService.resendVerification(
      access_token,
    );

    await this.redis.sadd(
      'whitelisted_access_tokens',
      newAccessToken.access_token,
    );

    return {
      success: true,
      message:
        'The verification email has been resent successfully. Please check your inbox and follow the instructions to verify your account.',
    };
  }

  @Post('/signin')
  @HttpCode(HttpStatus.OK)
  async signIn(
    @Session() session: Record<string, any>,
    @Body() user: LoginUserDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<UserAuthResponse> {
    // Checking user login
    const { access_token } = await this.authService.signIn(user);

    session.session_token = uuidv4();

    await this.redis.sadd('whitelisted_access_tokens', access_token);
    // Set access token
    res.cookie('access_token', access_token, {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });
    return {
      success: true,
      message: 'Successfully signed in!',
    };
  }

  // User google sign up controller
  // URL - auth/google/signin
  // Google user method
  @Get('/google/signin')
  // @Throttle(5, 60)
  @UseGuards(GoogleAuthGuard)
  async googleSignIn() {
    return { msg: 'Google Authentication' };
  }

  // User google authentication response listen controller
  // URL - auth/google/redirect
  // Google user method
  @Get('/google/redirect')
  @UseGuards(GoogleAuthGuard)
  async googleRedirect(
    @Req() req,
    @Session() session: Record<string, any>,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { access_token, message, path } =
      await this.authService.createGoogleUser(req.user);

    // If there is no token
    if (!access_token) {
      session.destroy();

      // Remove access token
      res.clearCookie('access_token', {
        domain: this.configService.get<string>('COOKIE_DOMAIN'),
        sameSite: 'none',
        secure: true,
        httpOnly: true,
      });
      return res.redirect(
        `${this.configService.get<string>(
          'FRONT_BASE_URL',
        )}/${path}?message=${message.toString()}`,
      );
    }

    
    session.session_token = uuidv4();

    await this.redis.sadd('whitelisted_access_tokens', access_token);

    // Set cookies by response
    res.cookie('access_token', access_token, {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });

    // Response
    return res.redirect(
      `${this.configService.get<string>(
        'FRONT_BASE_URL',
      )}/${path}?message=${message.toString()}`,
    );
  }

  // User logout controller
  // URL - auth/logout
  // Manual/Google
  @Get('/logout')
  // @Throttle(5, 60)
  @UseGuards(JwtCookieGuard, JwtGuard)
  async logout(
    @Session() session: Record<string, any>,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ) {
    if (!req.headers.authorization) {
      return {
        success: false,
        message: `Access denied! We couldn't locate an access token for your account.`,
      };
    }

    session.destroy();

    await this.redis.srem(
      'whitelisted_access_tokens',
      req.headers.authorization.replace('Bearer ', ''),
    );
    // Remove cookie
    res.clearCookie('access_token', {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });

    return {
      success: true,
      message:
        'You have been logged out successfully. We hope to see you again soon.',
    };
  }

  // User deactivate controller
  // URL - auth/deactivate-user
  // Mannual/Google
  @Put('/deactivate-user')
  // @Throttle(5, 60)
  @UseGuards(JwtCookieGuard, JwtGuard)
  async deactivateUser(
    @Req() req: Request,
    @Session() session: Record<string, any>,
    @Res({ passthrough: true }) res: Response,
  ) {
    // Deactivate user
    const { success, message } = await this.authService.deactivateUser(
      req.headers.authorization.replace('Bearer ', ''),
    );

    session.destroy();
    await this.redis.srem(
      'whitelisted_access_tokens',
      req.headers.authorization.replace('Bearer ', ''),
    );
    
    // Remove cookie
    res.clearCookie('access_token', {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });
    return {
      success: success,
      message: message,
    };
  }

  // Get user deatails controller
  // URL - auth/get-user
  // Mannual/Google
  @Get('/get-user')
  @UseGuards(JwtCookieGuard, JwtGuard)
  // @Roles('admin')
  async getUserDetails(@Req() req: Request): Promise<PublicUserDetails> {
    const isMember = await this.redis.sismember(
      'whitelisted_access_tokens',
      req.headers.authorization.replace('Bearer ', ''),
    );

    if (isMember == 0) {
      this.logger.warn('Invalid access token.');
      throw new UnauthorizedException('Invalid access token.');
    }

    return this.authService.getUserDetails(
      req.headers.authorization.replace('Bearer ', ''),
    );
  }

  // Update user password
  // URL - auth/update-password
  // Mannual user
  @Put('/update-password')
  // @Throttle(5, 60)
  @UseGuards(JwtCookieGuard, JwtGuard)
  async updateUserPassword(
    @Req() req: Request,
    @Session() session: Record<string, any>,
    @Body() updateUserPasswordDto: UpdateUserPasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { access_token } = await this.authService.updateUserPassword(
      req.headers.authorization.replace('Bearer ', ''),
      updateUserPasswordDto,
    );

    
    await this.redis.srem(
      'whitelisted_access_tokens',
      req.headers.authorization.replace('Bearer ', ''),
    );

    session.session_token = uuidv4();

    await this.redis.sadd('whitelisted_access_tokens', access_token);

    // Set access token to cookie
    res.cookie('access_token', access_token, {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });

    return {
      success: true,
      message: 'Your password has been updated successfully.',
    };
  }

  // Create new user password
  // URL - auth/create-new-password
  // Mannual user
  @Put('/create-new-password')
  // @throttle(5, 60)
  @UseGuards(JwtGuard)
  async createNewPassword(
    @Req() req: Request,
    @Session() session: Record<string, any>,
    @Body() createNewPasswordDto: CreateNewPasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    await this.authService.createNewPassword(
      req.headers.authorization.replace('Bearer ', ''),
      createNewPasswordDto,
    );

    session.destroy();

    await this.redis.srem(
      'whitelisted_access_tokens',
      req.headers.authorization.replace('Bearer ', ''),
    );
    
    // Remove cookie
    res.clearCookie('access_token', {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });

    return {
      success: true,
      message: 'New user password has been created successfully.',
    };
  }

  // Forgot password controller
  // URL - auth/forgot-password
  @Post('/forgot-password')

  // @Throttle(5, 60)
  async forgotPassword(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @Session() session: Record<string, any>,
  ) {
    // Send email after email validation
    const { access_token } = await this.authService.forgotPasswordEmailHandle(
      forgotPasswordDto,
    );

    
    session.session_token = uuidv4();

    await this.redis.sadd('whitelisted_access_tokens', access_token);

    return {
      success: true,
      message:
        'Password reset instructions have been sent. Confirm email address if no email received.',
    };
  }
  // Forgot password controller
  // URL - auth/forgot-password
  @Post('/reset-password-verification-send')

  // @Throttle(5, 60)
  async resetPasswordVerificationSend(
    @Body() forgotPasswordDto: ForgotPasswordDto,
    @Session() session: Record<string, any>,
  ) {
    // Send email after email validation
    const { access_token } = await this.authService.resetPasswordEmailHandle(
      forgotPasswordDto,
    );

    
    session.session_token = uuidv4();

    await this.redis.sadd('whitelisted_access_tokens', access_token);

    return {
      success: true,
      message:
        'Password reset instructions have been sent. Confirm email address if no email received.',
    };
  }

  // Controller for reset the user password
  // URL - auth/reset-password
  @Post('/reset-password')
  // @Throttle(5, 60)
  @UseGuards(JwtCookieGuard, JwtGuard)
  async resetPassword(
    @Req() req: Request,
    @Session() session: Record<string, any>,
    @Body() resetPasswordDto: ResetPasswordDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    // Handle reset password
    const { access_token } = await this.authService.resetPassword(
      req.headers.authorization.replace('Bearer ', ''),
      resetPasswordDto,
    );

    await this.redis.srem(
      'whitelisted_access_tokens',
      req.headers.authorization.replace('Bearer ', ''),
    );

    session.session_token = uuidv4();

    await this.redis.sadd('whitelisted_access_tokens', access_token);

    // Set access token to cookie
    res.cookie('access_token', access_token, {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });

    return {
      succcess: true,
      message: 'Password has been reset successfully.',
    };
  }

  // Controller for reset the user password
  // URL - auth/reset-password
  @Post('/verify-code')
  // @Throttle(5, 60)
  @UseGuards(JwtCookieGuard, JwtGuard)
  async verifyCode(
    @Req() req: Request,
    @Session() session: Record<string, any>,
    @Body() verifyCodeDto: VerifyCodeDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    // Handle reset password
    const { access_token } = await this.authService.verifyCode(
      req.headers.authorization.replace('Bearer ', ''),
      verifyCodeDto,
    );

    await this.redis.srem(
      'whitelisted_access_tokens',
      req.headers.authorization.replace('Bearer ', ''),
    );

    session.session_token = uuidv4();

    await this.redis.sadd('whitelisted_access_tokens', access_token);

    // Set access token to cookie
    res.cookie('access_token', access_token, {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });

    return {
      succcess: true,
      message: 'Verification Code is Validated successfully.',
    };
  }

  // Update user details
  // URL - auth/update-user-info
  // Manual
  @Put('/update-user-info')
  // @Throttle(5, 60)
  @UseGuards(JwtCookieGuard, JwtGuard)
  async updateUserInfo(
    @Req() req: Request,
    @Body() updateUserInfoDto: UpdateUserInfoDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { access_token } = await this.authService.updateUserInfo(
      req.headers.authorization.replace('Bearer ', ''),
      updateUserInfoDto,
    );

    await this.redis.srem(
      'whitelisted_access_tokens',
      req.headers.authorization.replace('Bearer ', ''),
    );

    await this.redis.sadd('whitelisted_access_tokens', access_token);

    //Set cookie
    res.cookie('access_token', access_token, {
      domain: this.configService.get<string>('COOKIE_DOMAIN'),
      sameSite: 'none',
      secure: true,
      httpOnly: true,
    });

    return {
      success: true,
      message: updateUserInfoDto.email
        ? `Your information has been updated successfully. We have sent a verification email to your new email address. Please verify it to update the email address.`
        : 'Your information has been updated successfully.',
    };
  }

}
