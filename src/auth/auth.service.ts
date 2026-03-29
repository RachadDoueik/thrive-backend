import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { createHash, randomBytes } from 'crypto';

export type SupabaseTokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  expires_at?: number;
  refresh_token?: string;
  user?: unknown;
};

@Injectable()
export class AuthService {
  private supabaseClient: SupabaseClient;

  constructor(private readonly configService: ConfigService) {
    const supabaseUrl = this.getSupabaseUrl();
    const supabaseAnonKey = this.getSupabaseAnonKey();

    this.supabaseClient = createClient(supabaseUrl, supabaseAnonKey, {
      auth: {
        persistSession: false,
        autoRefreshToken: false,
        detectSessionInUrl: false,
      },
    });
  }

  getSupabaseUrl() {
    const value =
      this.configService.get<string>('SUPABASE_URL') ??
      this.configService.get<string>('VITE_SUPABASE_URL');

    if (!value) {
      throw new InternalServerErrorException(
        'Missing SUPABASE_URL (or VITE_SUPABASE_URL) in environment',
      );
    }

    return value;
  }

  getSupabaseAnonKey() {
    const value =
      this.configService.get<string>('SUPABASE_ANON_KEY') ??
      this.configService.get<string>('VITE_SUPABASE_ANON_KEY');

    if (!value) {
      throw new InternalServerErrorException(
        'Missing SUPABASE_ANON_KEY (or VITE_SUPABASE_ANON_KEY) in environment',
      );
    }

    return value;
  }

  async signInWithEmail(email: string, password: string) {
    const { data, error } = await this.supabaseClient.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      return { data: null, error };
    }

    return { data, error: null };
  }

  async signUpWithEmail(email: string, password: string) {
    const { data, error } = await this.supabaseClient.auth.signUp({
      email,
      password,
    });

    if (error) {
      return { data: null, error };
    }

    return { data, error: null };
  }

  async getUserFromAccessToken(accessToken: string) {
    const { data, error } = await this.supabaseClient.auth.getUser(accessToken);

    if (error) {
      return { user: null, error };
    }

    return { user: data.user ?? null, error: null };
  }

  private base64UrlEncode(input: Buffer) {
    return input
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
  }

  private base64UrlDecodeToString(input: string) {
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const padLength = (4 - (base64.length % 4)) % 4;
    const padded = base64 + '='.repeat(padLength);
    return Buffer.from(padded, 'base64').toString('utf8');
  }

  private sha256Base64Url(input: string) {
    const hash = createHash('sha256').update(input).digest();
    return this.base64UrlEncode(hash);
  }

  createGoogleSignInUrl(params: {
    callbackUrl: string;
    next?: string;
  }): { url: string; codeVerifier: string } {
    const supabaseUrl = this.getSupabaseUrl();

    const redirectTo = new URL(params.callbackUrl);
    if (params.next) {
      redirectTo.searchParams.set('next', params.next);
    }

    const codeVerifier = this.base64UrlEncode(randomBytes(32));
    const codeChallenge = this.sha256Base64Url(codeVerifier);

    const url = new URL(`${supabaseUrl}/auth/v1/authorize`);
    url.searchParams.set('provider', 'google');
    url.searchParams.set('redirect_to', redirectTo.toString());
    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_challenge_method', 's256');

    return { url: url.toString(), codeVerifier };
  }

  decodeState(state?: string): { next?: string } {
    if (!state) return {};
    try {
      const json = this.base64UrlDecodeToString(state);
      const parsed = JSON.parse(json);
      if (!parsed || typeof parsed !== 'object') return {};
      if ('next' in parsed && typeof parsed.next === 'string') {
        return { next: parsed.next };
      }
      return {};
    } catch {
      return {};
    }
  }

  async exchangeGoogleCodeForSession(params: {
    code: string;
    codeVerifier: string;
  }): Promise<SupabaseTokenResponse> {
    const supabaseUrl = this.getSupabaseUrl();
    const supabaseAnonKey = this.getSupabaseAnonKey();

    const response = await fetch(
      `${supabaseUrl}/auth/v1/token?grant_type=pkce`,
      {
        method: 'POST',
        headers: {
          apikey: supabaseAnonKey,
          Authorization: `Bearer ${supabaseAnonKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          auth_code: params.code,
          code_verifier: params.codeVerifier,
        }),
      },
    );

    const json = (await response.json().catch(() => null)) as unknown;

    if (!response.ok || !json || typeof json !== 'object') {
      throw new InternalServerErrorException(
        `Supabase token exchange failed (${response.status})`,
      );
    }

    return json as SupabaseTokenResponse;
  }
}
