import { ForbiddenException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import mongoose, { Model } from 'mongoose';
import { IUser } from 'src/user/user.model';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(
    @InjectModel('User') private readonly userModel: Model<IUser>,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signUp(dto: AuthDto) {
    try {
      //generate  hashed password
      const hash = await argon.hash(dto.password);
      const newUser = new this.userModel({
        email: dto.email,
        password: hash,
      });
      const document = await newUser.save();
      return document._id;
    } catch (error) {
      if (error.name === 'MongoServerError' && error.code === 11000) {
        throw new ForbiddenException('Credentials taken');
      }
      throw error;
    }
  }

  async signIn(dto: AuthDto) {
    const user = await this.userModel.findOne({ email: dto.email });
    if (!user) throw new ForbiddenException('Credentials incorrect');
    const passMatches = await argon.verify(user.password, dto.password);
    if (!passMatches) throw new ForbiddenException('Credentials incorrect');
    return this.signToken(user._id, user.email);
  }

  async signToken(
    userId: mongoose.Types.ObjectId,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');
    const token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret: secret,
    });

    return {
      access_token: token,
    };
  }
}
