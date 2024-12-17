import { DynamicModule, Module, Provider } from '@nestjs/common';
import { OAuth2Controller } from './oauth2.controller';
import { OAuth2Service, TokenStorageService, SessionService } from './services';
import { OAUTH2_CONFIG, OAUTH2_PROVIDER, OAUTH2_MODULE_OPTIONS } from './constants';
import { OAuth2ProviderConfig } from './interfaces';
import { KeycloakProvider } from './providers';

export interface OAuth2ModuleOptions {
  provider: 'keycloak' | 'auth0' | 'azure-ad';
  config: OAuth2ProviderConfig;
}

@Module({})
export class OAuth2Module {
  static register(options: OAuth2ModuleOptions): DynamicModule {
    const providers: Provider[] = [
      {
        provide: OAUTH2_MODULE_OPTIONS,
        useValue: options,
      },
      {
        provide: OAUTH2_CONFIG,
        useValue: options.config,
      },
      {
        provide: OAUTH2_PROVIDER,
        useFactory: (config: OAuth2ProviderConfig) => {
          switch (options.provider) {
            case 'keycloak':
              return new KeycloakProvider(config);
            default:
              throw new Error(`Unsupported provider: ${options.provider}`);
          }
        },
        inject: [OAUTH2_CONFIG],
      },
      {
        provide: SessionService,
        useFactory: (config: OAuth2ProviderConfig) => {
          return new SessionService(config.cookieSecret);
        },
        inject: [OAUTH2_CONFIG],
      },
      TokenStorageService,
      OAuth2Service,
    ];

    return {
      module: OAuth2Module,
      providers,
      exports: [OAuth2Service, OAUTH2_PROVIDER],
      controllers: [OAuth2Controller],
    };
  }
}