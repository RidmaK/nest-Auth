import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  UserDeactivationDetails,
  UserVerificationDetails,
} from '../user/interfaces/user.interface';

@Injectable()
export class EmailService {
  constructor(
    private mailerService: MailerService,
    private configService: ConfigService,
  ) {}

  // Send a veriifcation email to user's email address
  async sendVerificationEmail(
    userVerificationDetails: UserVerificationDetails,
    access_token: string,
  ): Promise<void> {
    try {
      const currentDate = new Date();
      const presentYear = currentDate.getFullYear();

      const { first_name, last_name, email, verification_code } =
        userVerificationDetails;
        
        // Making redirection URL
        const url = `${this.configService.get<string>(
          'FRONT_BASE_URL',
        )}/email-verification?verification_code=${verification_code}&access_token=${access_token}`;
          

      // Handle SMTP for verification
      await this.mailerService.sendMail({
        to: email,
        subject: 'Verify Your Email Address',
        template: './verification',
        context: {
          first_name,
          last_name,
          url,
          email,
          verification_code,
          presentYear,
        },
      });


    } catch (err) {
      console.log("error mail",err);
    }
  }

  //Send forgot password email
  async sendForgotPasswordEmail(
    userVerificationDetails: UserVerificationDetails,
    access_token: string,
  ) {
    try {
      const currentDate = new Date();
      const presentYear = currentDate.getFullYear();

      const { first_name, last_name, email, verification_code } =
        userVerificationDetails;

      const url = `${this.configService.get<string>(
        'FRONT_BASE_URL',
      )}/create-new-password?access_token=${access_token}`;

      await this.mailerService.sendMail({
        to: email,
        subject: 'Password Reset',
        template: './forgotPassword',
        context: {
          first_name,
          last_name,
          url,
          email,
          verification_code,
          presentYear,
        },
      });
    } catch (err) {
      console.log(err);
    }
  }

  //Send forgot password email
  async sendResetPasswordEmail(
    userVerificationDetails: UserVerificationDetails,
    access_token: string,
  ) {
    try {
      const currentDate = new Date();
      const presentYear = currentDate.getFullYear();

      const { first_name, last_name, email, verification_code } =
        userVerificationDetails;

      await this.mailerService.sendMail({
        to: email,
        subject: 'Verify Code',
        template: './verifyCode',
        context: {
          first_name,
          last_name,
          email,
          verification_code,
          presentYear,
        },
      });
    } catch (err) {
      console.log(err);
    }
  }

  // Send account deactivation email to user
  async userDeactivateEmail(userDeactivationDetails: UserDeactivationDetails) {
    try {
      const currentDate = new Date();
      const presentYear = currentDate.getFullYear();

      const { first_name, last_name, email } = userDeactivationDetails;

      await this.mailerService.sendMail({
        to: email,
        subject: 'Account Deleted',
        template: './userDeactivation',
        context: {
          first_name,
          last_name,
          email,
          presentYear,
        },
      });
    } catch (err) {
      console.log(err);
    }
  }
}
