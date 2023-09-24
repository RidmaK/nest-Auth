import { IsNotEmpty, IsString, Matches, MinLength } from 'class-validator';

export class UpdateGoogleUserDto {
  @IsString()
  @IsNotEmpty({ message: 'Please add a your first name' })
  @MinLength(2, { message: 'Input minimun 2 charactors to first name' })
  first_name: string;

  @IsString()
  @IsNotEmpty({ message: 'Please add a your last name' })
  @MinLength(2, { message: 'Input minimun 2 charactors to last name' })
  last_name: string;

  @IsString()
  @IsNotEmpty({ message: 'Please add a valid google_access_token' })
  google_access_token: string;
}
