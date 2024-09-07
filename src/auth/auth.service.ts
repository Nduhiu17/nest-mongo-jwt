import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { SignupDto } from './dto/signup.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schema/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schema/refreshtoken.schema';
import { uuid } from 'uuidv4';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(RefreshToken.name)
    private refreshTokenModel: Model<RefreshToken>,
    private jwtService: JwtService,
  ) {}

  async signUp(signupDto: SignupDto) {
    const { email, password, name } = signupDto;
    const emailInUse = await this.userModel.findOne({ email: email });
    if (emailInUse) {
      throw new ConflictException('Email is already in use');
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    return await this.userModel.create({
      email,
      password: hashedPassword,
      name,
    });
  }

  async login(loginData: LoginDto) {
    const { email, password } = loginData;
    const user = await this.userModel.findOne({ email: email });
    if (!user) {
      throw new UnauthorizedException('Email is not registered');
    }

    const compareHash = await bcrypt.compare(password, user.password);
    if (!compareHash) {
      throw new UnauthorizedException('Password is incorrect');
    }
    return await this.generateUserTokens(user._id);
  }

  async refreshToken(refreshToken: string) {
    const token = await this.refreshTokenModel.findOne({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('Refresh token is invalid');
    }
    return this.generateUserTokens(token.userId);
  }

  async generateUserTokens(userId) {
    const token = this.jwtService.sign({ userId }, { expiresIn: '1hr' });
    const refreshToken = uuid();
    await this.storeRefreshToken(refreshToken, userId);
    return { token, refreshToken };
  }

  storeRefreshToken = async (token: string, userId: string) => {
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);
    await this.refreshTokenModel.updateOne(
      { userId },
      { $set: { expiryDate, token } },
      { upsert: true },
    );
  };
}
