import {
    Injectable,
    UnauthorizedException,
    BadRequestException,
  } from '@nestjs/common';
  import { OAuth2Provider, OAuth2Token, OAuth2User } from '../interfaces';
  import { TokenStorageService } from './token-storage.service';
  import { SessionService } from './session.service';
  
  @Injectable()
  export class OAuth2Service {
    constructor(
      private readonly provider: OAuth2Provider,
      private readonly tokenStorage: TokenStorageService,
      private readonly sessionService: SessionService,
    ) {}
  
    async initiateAuth(): Promise<{ redirectUrl: string; state: string }> {
      const state = this.sessionService.generateState();
      const nonce = this.sessionService.generateNonce();
      
      await this.tokenStorage.storeState(state, nonce);
      
      const redirectUrl = this.provider.getAuthorizationUrl(state);
      return { redirectUrl, state };
    }
  
    async handleCallback(
      code: string,
      state: string,
    ): Promise<{ sessionId: string; expiresIn: number }> {
      const storedNonce = await this.tokenStorage.validateState(state);
      if (!storedNonce) {
        throw new BadRequestException('Invalid state parameter');
      }
  
      const tokens = await this.provider.getTokenFromCode(code);
      const sessionId = this.sessionService.createSession();
      
      await this.tokenStorage.storeTokens(sessionId, tokens);
      
      return {
        sessionId,
        expiresIn: tokens.expires_in,
      };
    }
  
    async refreshSession(sessionId: string): Promise<{ expiresIn: number }> {
      const tokens = await this.tokenStorage.getTokens(sessionId);
      if (!tokens?.refresh_token) {
        throw new UnauthorizedException('No valid session found');
      }
  
      try {
        const newTokens = await this.provider.refreshToken(tokens.refresh_token);
        await this.tokenStorage.storeTokens(sessionId, newTokens);
        
        return { expiresIn: newTokens.expires_in };
      } catch (error) {
        await this.tokenStorage.removeTokens(sessionId);
        throw new UnauthorizedException('Failed to refresh session');
      }
    }
  
    async logout(sessionId: string): Promise<void> {
      const tokens = await this.tokenStorage.getTokens(sessionId);
      if (tokens) {
        try {
          await this.provider.revokeToken(tokens.access_token);
        } catch (error) {
          console.error('Error revoking token:', error);
        }
        await this.tokenStorage.removeTokens(sessionId);
      }
    }
  
    async getUserInfo(sessionId: string): Promise<OAuth2User> {
      const tokens = await this.tokenStorage.getTokens(sessionId);
      if (!tokens) {
        throw new UnauthorizedException('No valid session found');
      }
  
      try {
        return await this.provider.getUserInfo(tokens.access_token);
      } catch {
        throw new UnauthorizedException('Invalid or expired session');
      }
    }
  
    async validateSession(sessionId: string): Promise<boolean> {
      const tokens = await this.tokenStorage.getTokens(sessionId);
      if (!tokens) {
        return false;
      }
  
      try {
        return await this.provider.validateToken(tokens.access_token);
      } catch {
        return false;
      }
    }
  }