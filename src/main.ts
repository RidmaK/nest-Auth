import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { ValidationPipe } from '@nestjs/common';
import * as passport from 'passport';
import * as session from 'express-session';
import { WinstonModule } from 'nest-winston';
import * as winston from 'winston';
import { Logtail } from '@logtail/node';
import * as cookieParser from 'cookie-parser';
import * as bodyParser from 'body-parser';
import { LogtailTransport } from '@logtail/winston';
import RedisStore from 'connect-redis';
import { Redis } from 'ioredis';
import { useContainer } from 'class-validator';

const logtail = new Logtail('jD12xBcwznyzQRZAVEYCWaXg');
async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger({
      transports: [
        new LogtailTransport(logtail),
        new winston.transports.Console({
          format: winston.format.simple(),
        }),
      ],
    }),
  });
  const configService = app.get(ConfigService);
  const port = configService.get('PORT');
  const redisClient = new Redis({
    host: configService.get('REDIS_HOST'),
    port: configService.get('REDIS_PORT'),
    password: configService.get('REDIS_PASSWORD'),
  });
  // app.setGlobalPrefix('api');
  app.use(cookieParser());
  app.use(
    session({
      secret: configService.get('JWT_SECRET'),
      name: 'auth',
      store: new RedisStore({
        client: redisClient,
        prefix: 'auth-session:',
      }),
      saveUninitialized: false,
      resave: false,
      cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 },
    }),
  );
  app.use(passport.initialize());
  app.use(passport.session());
  app.enableCors({
    origin: ['http://localhost:3001', 'http://localhost:3000'],
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    preflightContinue: false,
    credentials: true,
    allowedHeaders: [
      'Content-Type',
      'Origin',
      'X-Requested-With',
      'Accept',
      'x-client-key',
      'x-client-token',
      'x-client-secret',
      'Authorization',
    ],
  });
  app.useGlobalPipes(new ValidationPipe());
  useContainer(app.select(AppModule), { fallbackOnErrors: true });
  await app.listen(port);
}
bootstrap();
