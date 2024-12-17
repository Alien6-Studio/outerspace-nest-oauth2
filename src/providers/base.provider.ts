import { Injectable } from '@nestjs/common';
import {
  OAuth2Provider,
  OAuth2ProviderConfig,
  OAuth2Token,
  OAuth2User,
} from '../interfaces';

@Injectable()
export abstract class BaseOAuth2Provider implements OAuth2Provider {
  protected constructor(protected readonly config: OAuth2ProviderConfig) {}

  abstract getAuthorizationUrl(state: string): string;
  
  abstract getTokenFromCode(code: string): Promise<OAuth2Token>;
  
  abstract refreshToken(refreshToken: string): Promise<OAuth2Token>;
  
  abstract revokeToken(token: string): Promise<void>;
  
  abstract getUserInfo(accessToken: string): Promise<OAuth2User>;
  
  abstract validateToken(accessToken: string): Promise<boolean>;

  protected async makeRequest<T>(
    url: string,
    options: RequestInit = {},
  ): Promise<T> {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    return response.json();
  }

  protected createQueryString(params: Record<string, string>): string {
    return new URLSearchParams(params).toString();
  }
}