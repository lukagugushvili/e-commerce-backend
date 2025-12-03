import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { UsersService } from '../users/users.service';
import { LoginDto } from './dto/login.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ILoginResponse } from '../interface/login-response.interface';
import { IPayload } from '../interface/payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async register(dto: CreateUserDto): Promise<{ message: string }> {
    try {
      await this.usersService.createUser(dto);

      return { message: 'Registration successfully' };
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  async login(dto: LoginDto): Promise<ILoginResponse> {
    const { email, password } = dto;

    const user = await this.usersService.findUserByEmail(email);
    if (!user) throw new UnauthorizedException('Invalid credentials!');

    const compare = await bcrypt.compare(password, user.password);
    if (!compare) throw new UnauthorizedException('Invalid credentials!');

    const payload = { sub: user.id, email, role: user.role };

    const tokens = await this.generateTokens(payload);
    const { access_token, hashed } = tokens;

    await this.usersService.updateRefreshToken(payload.sub, hashed);

    return { userId: user.id, email, access_token, refresh_token: hashed };
  }

  private async generateTokens(payload: IPayload) {
    const access_token = this.jwt.sign(payload, {
      secret: this.config.get<string>('ACCESS_TOKEN_SECRET_KEY'),
      expiresIn: this.config.get('ACCESS_TOKEN_EXPIRE'),
    });

    const refresh_token = this.jwt.sign(payload, {
      secret: this.config.get<string>('REFRESH_TOKEN_SECRET_KEY'),
      expiresIn: this.config.get('REFRESH_TOKEN_EXPIRE'),
    });

    const salt = Number(this.config.get<string>('REFRESH_TOKEN_SALT_ROUNDS'));
    const hashed = await bcrypt.hash(refresh_token, salt);

    return { access_token, hashed };
  }
}
