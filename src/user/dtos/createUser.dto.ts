import {
  IsNotEmpty,
  IsString,
  Matches,
  MinLength,
  MaxLength,
  IsOptional,
  Length,
  IsEnum,
} from 'class-validator';
import { IsNull } from 'typeorm';
import { ApiProperty } from '@nestjs/swagger';

import { Status } from '../types/user.types';

export class CreateUserDto {
  @IsString()
  @IsNotEmpty({ message: 'Please add a your first name' })
  first_name: string;

  @IsString()
  @IsNotEmpty({ message: 'Please add a your last name' })
  last_name: string;

  @IsString()
  @ApiProperty()
  @Matches(/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, {
    message: 'Please add a valid email',
  })
  email: string;

  @IsString()
  @MinLength(8, { message: 'Input minimun 8 charactors to password' })
  password: string;

  @IsOptional()
  @Length(6)
  verification_code?: number;
  
  @IsOptional()
  @IsEnum([
    Status.ACTIVE,
    Status.BANNED,
    Status.DEACTIVATED,
    Status.INACTIVE,
    Status.PENDING,
  ])
  status?: Status;
}
