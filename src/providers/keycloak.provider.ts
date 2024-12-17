import { Injectable } from '@nestjs/common';
import {
  OAuth2Provider,
  OAuth2ProviderConfig,
  OAuth2Token,
  OAuth2User,
} from '../interfaces';
import { BaseOAuth2Provider } from './base.provider';

interface KeycloakConfig extends OAuth2ProviderConfig {
  realm: string;
}

@Injectable()
export class KeycloakProvider extends BaseOAuth2Provider implements OAuth2Provider {
  private readonly realmUrl: string;

  constructor(protected readonly config: KeycloakConfig) {
    super(config);
    this.realmUrl = `${config.authServerUrl}/realms/${config.realm}`;
  }

  getAuthorizationUrl(state: string): string {
    const params = {
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.callbackUrl,
      state,
      scope: this.config.scope || 'openid profile email',
    };

    return `${this.realmUrl}/protocol/openid-connect/auth?${this.createQueryString(params)}`;
  }

  async getTokenFromCode(code: string): Promise<OAuth2Token> {
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      code,
      redirect_uri: this.config.callbackUrl,
    });

    return this.makeRequest<OAuth2Token>(
      `${this.realmUrl}/protocol/openid-connect/token`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
      },
    );
  }

  async refreshToken(refreshToken: string): Promise<OAuth2Token> {
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      refresh_token: refreshToken,
    });

    return this.makeRequest<OAuth2Token>(
      `${this.realmUrl}/protocol/openid-connect/token`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
      },
    );
  }

  async revokeToken(token: string): Promise<void> {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      token,
    });

    await fetch(`${this.realmUrl}/protocol/openid-connect/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    });
  }

  async getUserInfo(accessToken: string): Promise<OAuth2User> {
    return this.makeRequest<OAuth2User>(
      `${this.realmUrl}/protocol/openid-connect/userinfo`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      },
    );
  }

  async validateToken(accessToken: string): Promise<boolean> {
    try {
      const introspection = await this.introspectToken(accessToken);
      return introspection.active === true;
    } catch {
      return false;
    }
  }

  async introspectToken(token: string): Promise<any> {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
      token,
    });

    return this.makeRequest<any>(
      `${this.realmUrl}/protocol/openid-connect/token/introspect`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: params.toString(),
      },
    );
  }

  decodeToken(token: string): any {
    try {
      const base64Url = token.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split('')
          .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
          .join(''),
      );

      return JSON.parse(jsonPayload);
    } catch (error) {
      return null;
    }
  }
}