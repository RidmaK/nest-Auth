import { Inject, Injectable } from '@nestjs/common';
import { PassportSerializer } from '@nestjs/passport';
import { UserRepository } from '../../user/repository/user.repository';

@Injectable()
export class SessionSerializer extends PassportSerializer {
  constructor(@Inject(UserRepository) private userRepository: UserRepository) {
    super();
  }

  serializeUser(user: any, done: Function) {
    done(null, user);
  }

  async deserializeUser(payload: any, done: Function) {
    const user = await this.userRepository.findById(payload.id);
    return user ? done(null, user) : done(null, null);
  }
}
