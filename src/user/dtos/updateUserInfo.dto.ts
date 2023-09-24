import {
  IsNotEmpty,
  IsString,
  Matches,
  MaxLength,
  MinLength,
  IsOptional,
  IsNumber,
  Length,
  validate,
  Validate,
} from 'class-validator';
import { UniqueFieldValidator } from 'src/validators/unique-field.validator';
import { User } from '../entity/user.entity';

export class UpdateUserInfoDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty({ message: 'Please add a your first name' })
  @MinLength(2, { message: 'Input minimun 2 charactors to first name' })
  first_name?: string;

  @IsOptional()
  @IsString()
  @IsNotEmpty({ message: 'Please add a your last name' })
  @MinLength(2, { message: 'Input minimun 2 charactors to last name' })
  last_name?: string;

  @IsOptional()
  @IsString()
  @Validate(UniqueFieldValidator, [User, 'username'])
  username?: string;

  @IsOptional()
  @IsString()
  phone?: string;

  @IsOptional()
  @IsString()
  description?: string;

  @IsOptional()
  @IsString()
  experience?: string;

  @IsOptional()
  @IsString()
  @Validate(UniqueFieldValidator, [User, 'email'])
  @Matches(/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, {
    message: 'Please add a valid email',
  })
  email?: string;
}
