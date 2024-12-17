import { Injectable } from '@nestjs/common';
import { OAuth2Token } from '../interfaces';
import Redis from 'ioredis';

@Injectable()
export class TokenStorageService {
  private readonly redis: Redis;

  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: parseInt(process.env.REDIS_PORT || '6379', 10),
    });
  }

  async storeTokens(sessionId: string, tokens: OAuth2Token): Promise<void> {
    await this.redis.set(
      `tokens:${sessionId}`,
      JSON.stringify(tokens),
      'EX',
      tokens.expires_in,
    );
  }

  async getTokens(sessionId: string): Promise<OAuth2Token | null> {
    const tokens = await this.redis.get(`tokens:${sessionId}`);
    return tokens ? JSON.parse(tokens) : null;
  }

  async removeTokens(sessionId: string): Promise<void> {
    await this.redis.del(`tokens:${sessionId}`);
  }

  async storeState(state: string, nonce: string): Promise<void> {
    await this.redis.set(`state:${state}`, nonce, 'EX', 600); // 10 minutes expiration
  }

  async validateState(state: string): Promise<string | null> {
    const nonce = await this.redis.get(`state:${state}`);
    if (nonce) {
      await this.redis.del(`state:${state}`);
    }
    return nonce;
  }
}