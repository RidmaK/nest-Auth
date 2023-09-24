import { MailerModule } from '@nestjs-modules/mailer';
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { EmailService } from './email.service';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';

@Module({
  imports: [
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        transport: {
          host: configService.get<string>('SENDING_BLUE_CLIENT_HOST'),
          port: 2525,
          secure: false,
          auth: {
            user: configService.get<string>('SENDING_BLUE_CLIENT_USER'),
            pass: configService.get<string>('SENDING_BLUE_CLIENT_PASSWORD'),
          },
          tls: {
            rejectUnauthorized: false, // Accept self-signed certificates
          },
        },
        defaults: {
          from: `${configService.get<string>(
            'SENDING_BLUE_CLIENT_TEMPLATE_DEFAULT_NAME',
          )} <${configService.get<string>(
            'SENDING_BLUE_CLIENT_TEMPLATE_DEFAULT_EMAIL',
          )}>`,
        },
        template: {
          dir:
            process.cwd() +
            configService.get<string>('SENDING_BLUE_CLIENT_TEMPLATE_DIR'),
          adapter: new HandlebarsAdapter(),
          options: {
            strict: true,
          },
        },
      }),
    }),
  ],
  providers: [EmailService],
  exports: [EmailService],
})
export class EmailModule {}
