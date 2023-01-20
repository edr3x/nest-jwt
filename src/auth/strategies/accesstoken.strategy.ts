import { Injectable } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import config from "src/config/default";
import { JwtPayload } from "../types";

@Injectable()
export class AccessTokenStrategy extends PassportStrategy(Strategy, "jwt") {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.ACCESS_TOKEN_SECRET,
      passReqToCallback: true,
    });
  }

  async validate(payload: JwtPayload) {
    return payload;
  }
}
