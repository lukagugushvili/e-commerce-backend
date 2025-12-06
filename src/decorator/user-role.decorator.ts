import { SetMetadata } from '@nestjs/common';
import { UserRoles } from '../enum/user-roles.enum';

export const USER_ROLES_KEY = 'roles';
export const Roles = (...roles: UserRoles[]) =>
  SetMetadata(USER_ROLES_KEY, roles);
