import { Injectable } from '@nestjs/common';
import { randomBytes } from 'crypto';
import { sign, verify } from 'jsonwebtoken';

@Injectable()
export class SessionService {
  constructor(private readonly cookieSecret: string) {}

  createSession(): string {
    return randomBytes(32).toString('hex');
  }

  createSessionCookie(sessionId: string, expiresIn: number): string {
    return sign({ sessionId }, this.cookieSecret, { expiresIn });
  }

  validateSessionCookie(cookie: string): string | null {
    try {
      const decoded = verify(cookie, this.cookieSecret) as { sessionId: string };
      return decoded.sessionId;
    } catch {
      return null;
    }
  }

  generateState(): string {
    return randomBytes(32).toString('hex');
  }

  generateNonce(): string {
    return randomBytes(32).toString('hex');
  }
}