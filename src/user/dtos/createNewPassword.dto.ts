import { IsString, MinLength } from 'class-validator';

export class CreateNewPasswordDto {
  @IsString({ message: 'Please add a valid password' })
  @MinLength(8, { message: 'Please add a valid password' })
  newPassword: string;

  @IsString({ message: 'Please add a valid password' })
  @MinLength(8, { message: 'Please add a valid password' })
  confirmPassword: string;
}
