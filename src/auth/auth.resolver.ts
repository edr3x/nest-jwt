import { Resolver, Query, Mutation, Args, Int } from "@nestjs/graphql";
import { AuthService } from "./auth.service";
import { Auth } from "./entities/auth.entity";
import { UpdateAuthInput } from "./dto/update-auth.input";
import { SignUpInput } from "./dto/signup-input";
import { SignResponse } from "./dto/sign-response";
import { SignInInput } from "./dto/signin-input";
import { LogoutResponse } from "./dto/logout-response";
import { Public } from "./decorators/public.decorator";
import { NewTokenResponse } from "./dto/newTokensResponse";
import { CurrentUserId } from "./decorators/currentUserId.decorator";
import { CurrentUser } from "./decorators/currentUser.docorator";
import { UseGuards } from "@nestjs/common";
import { RefreshTokenGuard } from "./guards/refreshToken.guard";

@Resolver(() => Auth)
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Mutation(() => SignResponse)
  signup(@Args("signUpInput") signUpInput: SignUpInput) {
    return this.authService.signup(signUpInput);
  }

  @Public()
  @Mutation(() => SignResponse)
  signin(@Args("signInInput") signInInput: SignInInput) {
    return this.authService.signin(signInInput);
  }

  @Query(() => Auth, { name: "auth" })
  findOne(@Args("id", { type: () => Int }) id: number) {
    return this.authService.findOne(id);
  }

  @Mutation(() => Auth)
  updateAuth(@Args("updateAuthInput") updateAuthInput: UpdateAuthInput) {
    return this.authService.update(updateAuthInput.id, updateAuthInput);
  }

  @Mutation(() => LogoutResponse)
  logout(@Args("id", { type: () => Int }) id: number) {
    return this.authService.logout(id);
  }

  @Query(() => String)
  hello() {
    return "Hello World";
  }

  @Public()
  @UseGuards(RefreshTokenGuard)
  @Mutation(() => NewTokenResponse)
  getNewTokens(
    @CurrentUserId() userId: number,
    @CurrentUser("refreshToken") refreshToken: string
  ) {
    return this.authService.getNewTokens(userId, refreshToken);
  }
}
