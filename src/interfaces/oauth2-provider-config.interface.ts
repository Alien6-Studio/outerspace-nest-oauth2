export interface OAuth2ProviderConfig {
    clientId: string;
    clientSecret: string;
    authServerUrl: string;
    realm: string;
    callbackUrl: string;
    scope?: string;
    cookieSecret: string;
    sessionSecret: string;
    cookieMaxAge?: number;
  }