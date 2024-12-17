import {
    Controller,
    Get,
    Post,
    Query,
    Res,
    Req,
    UnauthorizedException,
    UseGuards,
  } from '@nestjs/common';
  import { Response, Request } from 'express';
  import { OAuth2Service } from './services';
  import { OAuth2AuthGuard } from './guards';
  import { Public } from './decorators';
  import { DEFAULT_COOKIE_MAX_AGE, DEFAULT_COOKIE_NAME } from './constants';
  
  @Controller('auth')
  export class OAuth2Controller {
    constructor(private readonly oauth2Service: OAuth2Service) {}
  
    @Public()
    @Get('login')
    async login(@Res() res: Response) {
      const { redirectUrl } = await this.oauth2Service.initiateAuth();
      res.redirect(redirectUrl);
    }
  
    @Public()
    @Get('callback')
    async callback(
      @Query('code') code: string,
      @Query('state') state: string,
      @Res() res: Response,
    ) {
      try {
        const { sessionId, expiresIn } = await this.oauth2Service.handleCallback(
          code,
          state,
        );
  
        res.cookie(DEFAULT_COOKIE_NAME, sessionId, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          maxAge: DEFAULT_COOKIE_MAX_AGE,
        });
  
        res.redirect('/');
      } catch (error) {
        res.redirect('/auth/error');
      }
    }
  
    @Post('refresh')
    @UseGuards(OAuth2AuthGuard)
    async refresh(@Req() req: Request, @Res() res: Response) {
      try {
        const sessionId = req.cookies[DEFAULT_COOKIE_NAME];
        const { expiresIn } = await this.oauth2Service.refreshSession(sessionId);
  
        res.cookie(DEFAULT_COOKIE_NAME, sessionId, {
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          maxAge: DEFAULT_COOKIE_MAX_AGE,
        });
  
        res.json({ success: true });
      } catch (error) {
        throw new UnauthorizedException('Failed to refresh session');
      }
    }
  
    @Post('logout')
    @UseGuards(OAuth2AuthGuard)
    async logout(@Req() req: Request, @Res() res: Response) {
      const sessionId = req.cookies[DEFAULT_COOKIE_NAME];
      await this.oauth2Service.logout(sessionId);
  
      res.clearCookie(DEFAULT_COOKIE_NAME);
      res.json({ success: true });
    }
  
    @Get('session')
    @UseGuards(OAuth2AuthGuard)
    async getSession(@Req() req: Request) {
      const sessionId = req.cookies[DEFAULT_COOKIE_NAME];
      const user = await this.oauth2Service.getUserInfo(sessionId);
      return { user };
    }
  
    @Public()
    @Get('check')
    async checkSession(@Req() req: Request) {
      const sessionId = req.cookies[DEFAULT_COOKIE_NAME];
      if (!sessionId) {
        return { valid: false };
      }
  
      const isValid = await this.oauth2Service.validateSession(sessionId);
      return { valid: isValid };
    }
  }