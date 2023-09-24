import { IsString, MaxLength, MinLength } from 'class-validator';

export class UpdateUserPasswordDto {
  @IsString({ message: 'Please add a valid password' })
  @MinLength(8, { message: 'Please add a valid password' })
  currentPassword: string;

  @IsString({ message: 'Please add a valid password' })
  @MinLength(8, { message: 'Please add a valid password' })
  newPassword: string;
}
