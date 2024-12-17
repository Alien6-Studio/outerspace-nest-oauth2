import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { OAuth2User } from '../interfaces';

export const CurrentUser = createParamDecorator(
  (data: keyof OAuth2User | undefined, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;

    return data ? user?.[data] : user;
  },
);