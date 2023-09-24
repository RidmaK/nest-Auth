import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import { Inject, Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    configService: ConfigService,
    @Inject(AuthService) private readonly authService: AuthService,
  ) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID'),
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET'),
      callbackURL: `${configService.get<string>('BASE_URL')}/google/redirect`,
      scope: ['profile', 'email'],
    });
  }

  async validate(
    access_token: string,
    refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<any> {
    // Destructure google user fields
    const { name, emails, photos } = profile;
    const user = {
      first_name: name.givenName,
      last_name: name.familyName,
      email: emails[0].value,
      google_access_token: access_token,
    };

    //return the response
    done(null, user);
  }
}
