import { Module } from '@nestjs/common';
import { DatabaseModule } from './database/database.module';
import { UserModule } from './user/user.module';
import { AuthModule } from './auth/auth.module';
import { EmailModule } from './email/email.module';
import { PassportModule } from '@nestjs/passport';
import { ValidatorModule } from './validators/validator.module';

@Module({
  imports: [
    DatabaseModule,
    UserModule,
    AuthModule,
    EmailModule,
    ValidatorModule,
    PassportModule.register({ session: true }),
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
