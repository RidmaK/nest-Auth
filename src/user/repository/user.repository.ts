import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from '../entity/user.entity';
import { Repository } from 'typeorm';
import { CreateUserDto } from '../dtos/createUser.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { UpdateUserDto } from '../dtos/updateUser.dto';
import { CreateGoogleUserDto } from '../dtos/createGoogleUser.dto';
import { UpdateGoogleUserDto } from '../dtos/updateGoogleUser.dto';
import { RegisterType, Status } from '../types/user.types';
import { PublicUserDetails, UserId } from '../interfaces/user.interface';

@Injectable()
export class UserRepository {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async createUser(createUserDto: CreateUserDto) {
    try {
      const { first_name, last_name, email, password, verification_code } =
        createUserDto;

      const user = this.userRepository.create({
        first_name,
        last_name,
        email,
        password,
        verification_code,
      });

      const createdUser = await this.userRepository.save(user);

      return createdUser;
    } catch (error) {
      throw new Error(`Create User Error: ${error}`);
    }
  }

  // Find user by user id
  async findById(id: number): Promise<User> {
    try {
      return await this.userRepository.findOneBy({
        id: id,
      });
    } catch (err) {
      throw new Error(`Find By Id User Error: ${err}`);
    }
  }

  // Find user by user id
  async findByField(field: string, value: string): Promise<User> {
    try {
      const queryCondition = { [field]: value };

      // Find the user with the specified condition
      return await this.userRepository.findOne(queryCondition);
    } catch (err) {
      throw new Error(`Find By Id User Error: ${err}`);
    }
  }

  // Update user by id
  async updateById(id: number, user: UpdateUserDto): Promise<User> {
    try {
      // Update user
      await this.userRepository.update(id, user);

      return this.findById(id);
    } catch (err) {
      throw new Error(`Update By Id Error: ${err}`);
    }
  }

  // Get user details ( public details only )
  _getUserDetails(user: User): PublicUserDetails {
    return {
      id: user.id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      username: user.username,
      register_type: user.register_type,
      status: user.status,
      is_verified: user.is_verified,
      phone: user.phone,
      experience: user.experience,
      description: user.description,
    };
  }

  // Find the user by email
  async findByEmail(email: string): Promise<User> {
    try {
      return await this.userRepository.findOneBy({ email });
    } catch (err) {
      throw new Error(`Find By Email User Error: ${err}`);
    }
  }

  // Decode JWT token
  async _decodeJWT(token: string): Promise<any> {
    try {
      return this.jwtService.verify(token);
    } catch (err) {
      throw new Error(`Decode JWT Error: ${err}`);
    }
  }

  // Create google user in db
  // Google user
  async createGoogleUser(
    createGoogleUserDto: CreateGoogleUserDto,
  ): Promise<User> {
    try {
      const { first_name, last_name, email, google_access_token } =
        createGoogleUserDto;

      const user = await this.userRepository.create({
        first_name,
        last_name,
        email,
        google_access_token,
        is_verified: true,
        status: Status.ACTIVE,
        register_type: RegisterType.GOOGLE,
      });

      const createdGoogleUser = await this.userRepository.save(user);
      return createdGoogleUser;
    } catch (err) {
      throw new Error(`Create Google User Error: ${err}`);
    }
  }

  // Update the existing google user by user id
  async updateGoogleUserById(
    id: number,
    updateGoogleUserDto: UpdateGoogleUserDto,
  ): Promise<User> {
    try {
      // Update user
      await this.userRepository.update(id, updateGoogleUserDto);

      return await this.findById(id);
    } catch (err) {
      throw new Error(`Update Google User By Id Error: ${err}`);
    }
  }

  // Update user password by provided is
  async updatePasswordById(
    id: number,
    newDetails: { password: string; verification_code?: number },
  ): Promise<User> {
    try {
      // Update user
      await this.userRepository.update(id, newDetails);

      return await this.findById(id);
    } catch (err) {
      throw new Error(`Update Password By Id Error: ${err}`);
    }
  }

  // hashing the password
  async _hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt();
    return bcrypt.hash(password, salt);
  }

  // Code generate ( 6 numbers length ) for verify the user
  _verificationCodeGenerate(length: number): number {
    const randomNum: any = (
      Math.pow(10, length)
        .toString()
        .slice(length - 1) +
      Math.floor(Math.random() * Math.pow(10, length) + 1).toString()
    ).slice(-length);
    return Number(randomNum);
  }

  // Get user id of user
  _getUserId(userId: number): UserId {
    return {
      id: userId,
    };
  }

  // Check password match
  async _doesPasswordMatch(
    password: string,
    hashedPassword: string,
  ): Promise<boolean> {
    return bcrypt.compare(password, hashedPassword);
  }

  // Get user details ( public details only )
  _validatePassword(password: string) {
    const regex = /^(?=.*\d)(?=.*\W+)(?=.*[A-Z])(?=.*[a-z]).{8,}$/;

    if (!regex.test(password)) {
      if (password.length < 8) {
        return {
          success: false,
          message: 'The password must be at least 8 characters long.',
        };
      }

      if (!/[A-Z]/.test(password)) {
        return {
          success: false,
          message: 'The password must contain at least one uppercase letter.',
        };
      }
      if (!/[a-z]/.test(password)) {
        return {
          success: false,
          message: 'The password must contain at least one lowercase letter.',
        };
      }
      if (!/\d/.test(password)) {
        return {
          success: false,
          message: 'The password must contain at least one digit.',
        };
      }
      if (!/\W/.test(password)) {
        return {
          success: false,
          message: 'The password must contain at least one special character.',
        };
      }
    } else {
      return {
        success: true,
        message: 'The password is valid.',
      };
    }
  }
}
