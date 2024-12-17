export interface OAuth2Token {
    access_token: string;
    refresh_token?: string;
    id_token?: string;
    token_type: string;
    expires_in: number;
    scope?: string;
  }
  