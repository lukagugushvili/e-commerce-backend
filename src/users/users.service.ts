import {
  BadGatewayException,
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { User } from './schema/user.schema';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { ConfigService } from '@nestjs/config';
import { UpdateUserDto } from './dto/update-user.dto';
import { UserRoles } from '../enum/user-roles.enum';

@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private readonly configService: ConfigService,
  ) {}

  async createUser(dto: CreateUserDto): Promise<User> {
    const existingUser = await this.userModel.findOne({ email: dto.email });
    if (existingUser) throw new BadGatewayException('User already exist');

    const salt_rounds =
      Number(this.configService.get<string>('USER_PASSWORD_SALT_ROUNDS')) || 10;

    const hashedPassword = await bcrypt.hash(dto.password, salt_rounds);

    return this.userModel.create({
      ...dto,
      role: UserRoles.USER,
      password: hashedPassword,
    });
  }

  async findUserByEmail(email: string): Promise<User | null> {
    return await this.userModel.findOne({ email }).exec();
  }

  async updateRefreshToken(
    userId: string,
    refresh_token: string | null,
  ): Promise<User | null> {
    return await this.userModel
      .findByIdAndUpdate(userId, { refresh_token }, { new: true })
      .exec();
  }
}
