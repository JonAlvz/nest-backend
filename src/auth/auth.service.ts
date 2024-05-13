import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import { UpdateAuthDto } from './dto/update-auth.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from "bcryptjs";
import { LoginDto } from './dto/login.dto';
import { log } from 'console';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { promises } from 'dns';
import { LonginResponse } from './interfaces/login-response';
import { RegisterUSerDto } from './dto';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService,
  ) { }

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      //const newUser = new this.userModel(createUserDto);

      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel(
        {
          password: bcryptjs.hashSync(password, 10),
          ...userData
        }
      );
      await newUser.save();

      const { password: _, ...user } = newUser.toJSON();
      return user;

    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} ya existe`)
      }
      throw new InternalServerErrorException('No se esperaba llegar aqui')
    }
  }

  async register(data: RegisterUSerDto): Promise<LonginResponse> {

    const user = await this.create(data);

    return {
      user: user,
      token: this.getJwtToken({ id: user._id })
    }
  }

  async login(data: LoginDto): Promise<LonginResponse> {
    console.log({ data });

    const { email, password } = data;

    const user = await this.userModel.findOne({ email: email })

    if (!user) {
      throw new UnauthorizedException('Credenciales no validas - email')
    }
    if (!bcryptjs.compareSync(password, user.password)) {
      throw new UnauthorizedException('Credenciales no validas - contraseña')
    }

    const { password: _, ...restData } = user.toJSON();

    return {
      user: restData,
      token: this.getJwtToken({ id: user.id }),
    }

  }

  findAll(): Promise<User[]> {

    return this.userModel.find();
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload) {
    const token = this.jwtService.sign(payload);
    return token;
  }
}
