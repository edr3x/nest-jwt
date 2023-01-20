import {
  BadRequestException,
  ForbiddenException,
  Injectable,
} from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { SignUpInput } from "./dto/signup-input";
import { UpdateAuthInput } from "./dto/update-auth.input";
import { JwtService } from "@nestjs/jwt";
import config from "src/config/default";
import * as argon from "argon2";
import { SignInInput } from "./dto/signin-input";

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signup(signUpInput: SignUpInput) {
    const { username, password, email } = signUpInput;

    const doesExist = await this.prisma.user.findUnique({ where: { email } });

    if (doesExist) throw new BadRequestException("User already Exists");

    const hashedPassword = await argon.hash(password);

    const user = await this.prisma.user.create({
      data: {
        username,
        hashedPassword,
        email,
      },
    });

    const { accessToken, refreshToken } = await this.createToken(
      user.id,
      user.email
    );

    await this.updateRefreshToken(user.id, refreshToken);

    return { accessToken, refreshToken, user };
  }

  async signin(signInInput: SignInInput) {
    const user = await this.prisma.user.findUnique({
      where: { email: signInInput.email },
    });

    if (!user) throw new ForbiddenException("Access Denied");

    const doPasswordMatch = await argon.verify(
      user.hashedPassword,
      signInInput.password
    );

    if (!doPasswordMatch) throw new ForbiddenException("Access Denied");

    const { accessToken, refreshToken } = await this.createToken(
      user.id,
      user.email
    );

    await this.updateRefreshToken(user.id, refreshToken);

    return { accessToken, refreshToken, user };
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthInput: UpdateAuthInput) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  private async createToken(userId: number, email: string) {
    const accessToken = this.jwtService.sign(
      {
        userId,
        email,
      },
      { expiresIn: "1h", secret: config.ACCESS_TOKEN_SECRET }
    );

    const refreshToken = this.jwtService.sign(
      {
        userId,
        email,
        accessToken,
      },
      { expiresIn: "4h", secret: config.REFRESH_TOKEN_SECRET }
    );

    return { accessToken, refreshToken };
  }

  private async updateRefreshToken(userId: number, refreshToken: string) {
    const hashedRefreshToken = await argon.hash(refreshToken);

    await this.prisma.user.update({
      where: { id: userId },
      data: { hashedRefreshToken },
    });
  }

  async logout(userId: number) {
    await this.prisma.user.updateMany({
      where: {
        id: userId,
        hashedRefreshToken: { not: null },
      },
      data: {
        hashedRefreshToken: null,
      },
    });

    return { loggedOut: true };
  }

  async getNewTokens(userId: number, rt: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) throw new ForbiddenException("Access Denied");

    const doRefreshTokenMatch = await argon.verify(user.hashedRefreshToken, rt);

    if (!doRefreshTokenMatch) throw new ForbiddenException("Access Denied");

    const { refreshToken, accessToken } = await this.createToken(
      user.id,
      user.email
    );

    await this.updateRefreshToken(user.id, refreshToken);

    return { accessToken, refreshToken, user };
  }
}
