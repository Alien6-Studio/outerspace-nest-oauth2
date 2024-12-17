import { Test } from '@nestjs/testing';
import { KeycloakProvider } from '../../src/providers';
import { OAuth2ProviderConfig } from '../../src/interfaces';

/**
 * Test suite for KeycloakProvider
 * Tests the OAuth2/OIDC authentication flow implementation for Keycloak
 */
describe('KeycloakProvider', () => {
  let provider: KeycloakProvider;

  // Mock configuration for Keycloak provider tests
  const mockConfig: OAuth2ProviderConfig = {
    clientId: 'test-client',
    clientSecret: 'test-secret',
    authServerUrl: 'http://keycloak:8080/auth',
    realm: 'test-realm', // Required for Keycloak configuration
    callbackUrl: 'http://localhost:3000/callback',
    scope: 'openid profile email',
    cookieSecret: 'test-cookie-secret',
    sessionSecret: 'test-session-secret',
  };

  // Set up the testing module before each test
  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [
        {
          provide: KeycloakProvider,
          useValue: new KeycloakProvider(mockConfig),
        },
      ],
    }).compile();

    provider = moduleRef.get<KeycloakProvider>(KeycloakProvider);
  });

  /**
   * Tests for authorization URL generation
   * Verifies that the provider correctly builds the OAuth2 authorization URL
   */
  describe('getAuthorizationUrl', () => {
    it('should generate correct authorization URL', () => {
      const state = 'test-state';
      const url = provider.getAuthorizationUrl(state);

      // Basic URL parts
      expect(url).toContain(mockConfig.authServerUrl);
      expect(url).toContain(`/realms/${mockConfig.realm}`);
      expect(url).toContain('response_type=code');
      expect(url).toContain(`client_id=${mockConfig.clientId}`);
      expect(url).toContain(`redirect_uri=${encodeURIComponent(mockConfig.callbackUrl)}`);
      expect(url).toContain(`state=${state}`);
      
      // Updated scope test to handle '+' encoding for spaces
      const encodedScope = mockConfig.scope.replace(/ /g, '+');
      expect(url).toContain(`scope=${encodedScope}`);
    });
  });

  /**
   * Tests for token exchange functionality
   * Verifies the provider can successfully exchange authorization codes for tokens
   */
  describe('getTokenFromCode', () => {
    it('should exchange code for tokens', async () => {
      // Mock successful token response
      const mockTokenResponse = {
        access_token: 'test-access-token',
        refresh_token: 'test-refresh-token',
        expires_in: 300,
        token_type: 'Bearer',
        scope: 'openid profile email'
      };

      // Mock fetch response
      global.fetch = jest.fn().mockImplementationOnce(() =>
        Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockTokenResponse),
        }),
      );

      // Attempt to exchange code for tokens
      const result = await provider.getTokenFromCode('test-code');

      // Verify response and fetch call
      expect(result).toEqual(mockTokenResponse);
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('/token'),
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('grant_type=authorization_code'),
        }),
      );
    });

    it('should handle token request errors', async () => {
      // Mock failed token response
      global.fetch = jest.fn().mockImplementationOnce(() =>
        Promise.resolve({
          ok: false,
          status: 400,
        }),
      );

      // Verify error handling
      await expect(provider.getTokenFromCode('invalid-code')).rejects.toThrow();
    });
  });

  /**
   * Tests for token validation
   * Verifies the provider can correctly validate tokens with Keycloak
   */
  describe('validateToken', () => {
    it('should return true for valid token', async () => {
      // Mock successful validation response
      global.fetch = jest.fn().mockImplementationOnce(() =>
        Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ active: true }),
        }),
      );

      const result = await provider.validateToken('valid-token');
      expect(result).toBe(true);
    });

    it('should return false for invalid token', async () => {
      // Mock failed validation response
      global.fetch = jest.fn().mockImplementationOnce(() =>
        Promise.resolve({
          ok: false,
        }),
      );

      const result = await provider.validateToken('invalid-token');
      expect(result).toBe(false);
    });
  });
});