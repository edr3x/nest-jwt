import { Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { SignUpInput } from "./dto/signup-input";
import { UpdateAuthInput } from "./dto/update-auth.input";
import { JwtService } from "@nestjs/jwt";
import config from "src/config/default";
import * as argon from "argon2";

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwtService: JwtService) {}

  async signup(signUpInput: SignUpInput) {
    const { username, password, email } = signUpInput;
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

  findAll() {
    return `This action returns all auth`;
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
      { expiresIn: "10s", secret: config.ACCESS_TOKEN_SECRET }
    );

    const refreshToken = this.jwtService.sign(
      {
        userId,
        email,
        accessToken,
      },
      { expiresIn: "10s", secret: config.REFRESH_TOKEN_SECRET }
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
}
