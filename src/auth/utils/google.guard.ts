import { ExecutionContext, Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class GoogleAuthGuard extends AuthGuard('google') {
  async canActivate(context: ExecutionContext): Promise<any> {
    const activate = await super.canActivate(context);
    const request = context.switchToHttp().getRequest();
    await super.logIn(request);
    return activate;
  }
}
