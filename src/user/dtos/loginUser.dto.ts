import { IsString, Matches } from 'class-validator';

import { Status } from '../types/user.types';

export class LoginUserDto {
  @IsString()
  @Matches(/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, {
    message: 'Please add a valid email',
  })
  email: string;

  @IsString({ message: 'Please add a valid password' })
  password: string;
}
