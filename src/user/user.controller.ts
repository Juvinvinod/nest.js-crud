import { Controller, Get, UseGuards } from '@nestjs/common';
import { getUser } from 'src/auth/decorator';
import { JwtGuard } from 'src/auth/guard';
import { IUser } from './user.model';

@UseGuards(JwtGuard)
@Controller('users')
export class UserController {
  @Get('me')
  getMe(@getUser() user: IUser) {
    return user;
  }
}
