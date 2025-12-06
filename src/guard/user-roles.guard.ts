import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { USER_ROLES_KEY } from '../decorator/user-role.decorator';
import { UserRoles } from '../enum/user-roles.enum';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const requiredRoles = this.reflector.getAllAndOverride<UserRoles[]>(
      USER_ROLES_KEY,
      [context.getClass(), context.getHandler()],
    );

    if (!requiredRoles) throw true;

    const { user } = context.switchToHttp().getRequest();

    return requiredRoles.some((role) => user.role?.includes(role));
  }
}
