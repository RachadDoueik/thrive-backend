import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  (app.getHttpAdapter().getInstance() as any).set('trust proxy', 1);
  app.use(cookieParser());

  const corsOrigin =
    process.env.CORS_ORIGIN ??
    process.env.FRONTEND_URL ??
    process.env.FRONTEND_URLS;
  if (corsOrigin) {
    const origins = corsOrigin
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);

    app.enableCors({
      origin: origins,
      credentials: true,
    });
  }

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
