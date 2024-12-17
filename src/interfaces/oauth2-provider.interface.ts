import { OAuth2Token } from './oauth2-token.interface';
import { OAuth2User } from './oauth2-user.interface';

export interface OAuth2Provider {
  // Authentication flow
  getAuthorizationUrl(state: string): string;
  getTokenFromCode(code: string): Promise<OAuth2Token>;
  refreshToken(refreshToken: string): Promise<OAuth2Token>;
  revokeToken(token: string): Promise<void>;
  
  // User info and validation
  getUserInfo(accessToken: string): Promise<OAuth2User>;
  validateToken(accessToken: string): Promise<boolean>;
  
  // Optional methods for specific providers
  introspectToken?(token: string): Promise<any>;
  decodeToken?(token: string): any;
}