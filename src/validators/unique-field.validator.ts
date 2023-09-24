import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';
import { Body, Injectable } from '@nestjs/common';
import { UserRepository } from 'src/user/repository/user.repository';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/user/entity/user.entity';
import { Repository } from 'typeorm';

@ValidatorConstraint({ name: 'unique', async: true })
@Injectable()
export class UniqueFieldValidator implements ValidatorConstraintInterface {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
  ) {}

  validate = async (
    value: any,
    args: ValidationArguments,
  ): Promise<boolean> => {
    const [entityClass, fieldName] = args.constraints;

    const request = args.object;

    console.log(args);
    const entity = await this.userRepository.findOneBy({ [fieldName]: value });
    return !entity;
  };

  defaultMessage(args: ValidationArguments) {
    const [entityClass, fieldName] = args.constraints;
    return `${fieldName} must be unique`;
  }
}
