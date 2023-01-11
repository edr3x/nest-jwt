import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";

import config from "./config/default";

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(config.PORT);
}
bootstrap();
