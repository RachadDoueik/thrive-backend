import {
  BadRequestException,
  Body,
  Controller,
  Get,
  NotFoundException,
  Post,
  Query,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import type { Request, Response } from 'express';
import { ConfigService } from '@nestjs/config';
import { AuthService } from './auth.service';
import { UsersRepository } from '../users/users.repository';
import { Role } from 'generated/prisma/enums';

@Controller('auth')
export class AuthController {
  private readonly tokenCookieName: string;
  private readonly codeVerifierCookieName = 'sb-code-verifier';

  constructor(
    private readonly authService: AuthService,
    private readonly configService: ConfigService,
    private readonly usersRepository: UsersRepository,
  ) {
    this.tokenCookieName =
      this.configService.get<string>('SUPABASE_TOKEN_COOKIE') ??
      'sb-access-token';
  }

  private isProduction() {
    return (this.configService.get<string>('NODE_ENV') ?? '').toLowerCase() ===
      'production'
      ? true
      : false;
  }

  private getCookieOptions(params?: { maxAgeMs?: number }) {
    return {
      httpOnly: true,
      secure: this.isProduction(),
      sameSite: 'lax' as const,
      path: '/',
      ...(params?.maxAgeMs ? { maxAge: params.maxAgeMs } : {}),
    };
  }

  private getRequestBaseUrl(req: Request) {
    const proto =
      (req.headers['x-forwarded-proto'] as string | undefined)?.split(',')[0] ??
      req.protocol;
    return `${proto}://${req.get('host')}`;
  }

  @Get('google/signin')
  async signInWithGoogle(
    @Req() req: Request,
    @Res() res: Response,
    @Query('next') next?: string,
  ) {
    const callbackUrl = `${this.getRequestBaseUrl(req)}/auth/google/callback`;

    const { url, codeVerifier } = this.authService.createGoogleSignInUrl({
      callbackUrl,
      next,
    });

    res.cookie(
      this.codeVerifierCookieName,
      codeVerifier,
      this.getCookieOptions({ maxAgeMs: 10 * 60 * 1000 }),
    );

    const accept = (req.headers['accept'] as string | undefined) ?? '';
    const secFetchMode = (req.headers['sec-fetch-mode'] as string | undefined) ?? '';
    const isNavigation = secFetchMode === 'navigate';
    const wantsJson =
      !isNavigation &&
      (accept.includes('application/json') ||
        (req.headers['x-requested-with'] as string | undefined) ===
          'XMLHttpRequest');

    if (wantsJson) {
      return res.status(200).json({ url });
    }

    return res.redirect(302, url);
  }

  @Get('google/callback')
  async authWithGoogle(
    @Req() req: Request,
    @Res() res: Response,
    @Query('code') code?: string,
    @Query('state') state?: string,
    @Query('next') nextQuery?: string,
  ) {
    if (!code) {
      throw new BadRequestException('Missing OAuth code');
    }

    const codeVerifier = (req as any).cookies?.[this.codeVerifierCookieName] as
      | string
      | undefined;

    if (!codeVerifier) {
      throw new BadRequestException(
        'Missing code verifier cookie (start at /auth/google/signin)',
      );
    }

    const tokens = await this.authService.exchangeGoogleCodeForSession({
      code,
      codeVerifier,
    });

    res.clearCookie(this.codeVerifierCookieName, this.getCookieOptions());

    res.cookie(
      this.tokenCookieName,
      tokens.access_token,
      this.getCookieOptions({ maxAgeMs: tokens.expires_in * 1000 }),
    );

    const next = nextQuery ?? this.authService.decodeState(state).next;
    const frontendUrlRaw =
      this.configService.get<string>('FRONTEND_URL') ??
      this.configService.get<string>('FRONTEND_URLS') ??
      this.configService.get<string>('CORS_ORIGIN');

    const frontendUrl = frontendUrlRaw
      ?.split(',')
      .map((value) => value.trim())
      .filter(Boolean)[0];

    if (frontendUrl && next && next.startsWith('/') && !next.startsWith('//')) {
      return res.redirect(302, `${frontendUrl}${next}`);
    }

    return res.status(200).json({ user: tokens.user ?? null });
  }

  @Get('me')
  async me(@Req() req: Request) {
    const accessToken = (req as any).cookies?.[this.tokenCookieName] as
      | string
      | undefined;

    if (!accessToken) {
      throw new UnauthorizedException('Not authenticated');
    }

    const { user, error } = await this.authService.getUserFromAccessToken(
      accessToken,
    );

    if (error || !user) {
      throw new UnauthorizedException('Invalid or expired session');
    }

    return { user };
  }

  @Get('me/role')
  async myRole(@Req() req: Request) {
    const accessToken = (req as any).cookies?.[this.tokenCookieName] as
      | string
      | undefined;

    if (!accessToken) {
      throw new UnauthorizedException('Not authenticated');
    }

    const { user, error } = await this.authService.getUserFromAccessToken(
      accessToken,
    );

    const email = (user as any)?.email as string | undefined;
    if (error || !user || !email) {
      throw new UnauthorizedException('Invalid or expired session');
    }

    const appUser = await this.usersRepository.userByEmail(email);
    if (!appUser) {
      throw new NotFoundException('User not found');
    }

    return { role: appUser.role };
  }

  @Post('me/role')
  async updateMyRole(
    @Req() req: Request,
    @Body() body: { role?: string },
  ) {
    const accessToken = (req as any).cookies?.[this.tokenCookieName] as
      | string
      | undefined;

    if (!accessToken) {
      throw new UnauthorizedException('Not authenticated');
    }

    const { user, error } = await this.authService.getUserFromAccessToken(
      accessToken,
    );

    const email = (user as any)?.email as string | undefined;
    if (error || !user || !email) {
      throw new UnauthorizedException('Invalid or expired session');
    }

    const role = body.role?.trim().toUpperCase();
    const allowedRoles = Object.values(Role);
    if (!role || !allowedRoles.includes(role as Role)) {
      throw new BadRequestException(
        `role must be one of: ${allowedRoles.join(', ')}`,
      );
    }

    const updated = await this.usersRepository.updateRoleByEmail(
      email,
      role as Role,
    );

    if (!updated) {
      throw new NotFoundException('User not found');
    }

    return { role: updated.role };
  }

  @Post('logout')
  async logout(@Res() res: Response) {
    res.clearCookie(this.tokenCookieName, this.getCookieOptions());
    res.clearCookie(this.codeVerifierCookieName, this.getCookieOptions());
    return res.status(204).send();
  }

  @Post('email/signin')
  async signInWithEmail(
    @Res({ passthrough: true }) res: Response,
    @Body() body: { email?: string; password?: string },
  ) {
    const email = body.email?.trim();
    const password = body.password;

    if (!email || !password) {
      throw new BadRequestException('email and password are required');
    }

    const { data, error } = await this.authService.signInWithEmail(
      email,
      password,
    );

    if (error || !data?.session) {
      throw new UnauthorizedException(error?.message ?? 'Invalid credentials');
    }

    res.cookie(
      this.tokenCookieName,
      data.session.access_token,
      this.getCookieOptions({ maxAgeMs: data.session.expires_in * 1000 }),
    );

    return { user: data.user };
  }

  @Post('email/signup')
  async createAccount(
    @Res({ passthrough: true }) res: Response,
    @Body() body: { email?: string; password?: string },
  ) {
    const email = body.email?.trim();
    const password = body.password;

    if (!email || !password) {
      throw new BadRequestException('email and password are required');
    }

    const { data, error } = await this.authService.signUpWithEmail(
      email,
      password,
    );

    if (error) {
      throw new BadRequestException(error.message);
    }

    if (data?.session) {
      res.cookie(
        this.tokenCookieName,
        data.session.access_token,
        this.getCookieOptions({ maxAgeMs: data.session.expires_in * 1000 }),
      );
    }

    return {
      user: data?.user ?? null,
      hasSession: Boolean(data?.session),
    };
  }
}
