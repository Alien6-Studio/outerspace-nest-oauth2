import {
    Injectable,
    CanActivate,
    ExecutionContext,
    UnauthorizedException,
  } from '@nestjs/common';
  import { Reflector } from '@nestjs/core';
  import { OAuth2Service } from '../services';
  import { IS_PUBLIC_KEY } from '../decorators';
  
  @Injectable()
  export class OAuth2AuthGuard implements CanActivate {
    constructor(
      private readonly reflector: Reflector,
      private readonly oauth2Service: OAuth2Service,
    ) {}
  
    async canActivate(context: ExecutionContext): Promise<boolean> {
      const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
        context.getHandler(),
        context.getClass(),
      ]);
  
      if (isPublic) {
        return true;
      }
  
      const request = context.switchToHttp().getRequest();
      const sessionId = request.cookies?.sessionId;
  
      if (!sessionId) {
        throw new UnauthorizedException('No session found');
      }
  
      const isValid = await this.oauth2Service.validateSession(sessionId);
      if (!isValid) {
        throw new UnauthorizedException('Invalid or expired session');
      }
  
      // Attach user info to request
      request.user = await this.oauth2Service.getUserInfo(sessionId);
      return true;
    }
  }