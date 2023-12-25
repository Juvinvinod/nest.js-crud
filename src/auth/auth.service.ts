import { ForbiddenException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { IUser } from 'src/user/user.model';
import { AuthDto } from './dto';
import * as argon from 'argon2';

@Injectable({})
export class AuthService {
  constructor(@InjectModel('User') private readonly userModel: Model<IUser>) {}

  login() {
    return { msg: 'I have logged in' };
  }

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
}
