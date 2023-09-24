import { Module } from '@nestjs/common';
import { UserModule } from '../user/user.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/user/entity/user.entity';
import { UniqueFieldValidator } from './unique-field.validator';
@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UniqueFieldValidator],
  exports: [UniqueFieldValidator],
})
export class ValidatorModule {}
