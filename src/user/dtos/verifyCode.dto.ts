import { IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator';

export class VerifyCodeDto {

  @IsNotEmpty({ message: 'Please enter the verification code' })
  verification_code: number;
}
