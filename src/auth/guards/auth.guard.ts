import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interfaces/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(private jwtService: JwtService, private authService: AuthService) { }

  async canActivate(context: ExecutionContext): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    // console.log({ request });
    // console.log({ token })

    if (!token) {
      throw new UnauthorizedException('Se esperaba Token');
    }

    try {
      const payload = await this.jwtService.verifyAsync(token, { secret: process.env.JWT_SEED });


      const user = await this.authService.findUserById(payload.id);

      request['user'] = user;
      if (!user) {
        throw new UnauthorizedException('Se esperaba Usuario');
      }

      if (!user.isActive) {
        throw new UnauthorizedException('Usuario no activo')
      }

    } catch (error) {
      throw new UnauthorizedException();
    }




    return Promise.resolve(true);
  }


  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
