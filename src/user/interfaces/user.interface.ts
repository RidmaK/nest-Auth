import { Status,RegisterType } from '../types/user.types';

export interface UserAuthResponse {
  success: boolean;
  message: string;
}

export interface UserId {
  id: number;
}

export interface UserDetails {
  id: number;
}


export interface UserVerificationDetails {
  first_name: string;
  last_name: string;
  email: string;
  verification_code: number;
}

export interface UserOTPVerificationDetails {
  first_name: string;
  last_name: string;
  email: string;
  otp_code: number;
}

export interface UserDeactivationDetails {
  first_name: string;
  last_name: string;
  email: string;
}

export interface PublicUserDetails {
  id: number;
  first_name: string;
  last_name: string;
  email: string;
  username: string;
  register_type: RegisterType;
  status: Status;
  is_verified: boolean;
  phone: string;
  experience: string;
  description: string;
  
}
