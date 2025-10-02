#!/usr/bin/env node
import { execSync } from "node:child_process";
import { mkdirSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";

const projectName = process.argv[2] || "nestjs-app";
const root = join(process.cwd(), projectName);
const sh = (cmd, opts = {}) => execSync(cmd, { stdio: "inherit", cwd: opts.cwd || root });

async function ask(prompts) {
  const rl = readline.createInterface({ input, output });
  const ans = {};
  for (const p of prompts) {
    const q = p.default ? `${p.q} (${p.default}): ` : `${p.q}: `;
    const v = (await rl.question(q)) || p.default || "";
    ans[p.name] = v;
  }
  await rl.close();
  return ans;
}

(async () => {
  const db = await ask([
    { name: "DB_HOST", q: "DB host", default: "localhost" },
    { name: "DB_PORT", q: "DB port", default: "5432" },
    { name: "DB_USER", q: "DB user", default: "postgres" },
    { name: "DB_PASS", q: "DB pass", default: "postgres" },
    { name: "DB_NAME", q: "DB name", default: projectName },
  ]);

  const admin = await ask([
    { name: "ADMIN_EMAIL", q: "Admin email", default: "admin@example.com" },
    { name: "ADMIN_PASSWORD", q: "Admin password", default: "admin123" },
    { name: "ADMIN_FULLNAME", q: "Admin full name", default: "Admin" },
  ]);

  if (!existsSync(root)) mkdirSync(root, { recursive: true });
  execSync(`npx @nestjs/cli new ${projectName} --package-manager npm`, { stdio: "inherit" });

  sh("npm i @nestjs/typeorm typeorm pg @nestjs/config");
  sh("npm i @nestjs/jwt @nestjs/passport passport passport-jwt");
  sh("npm i bcryptjs");
  sh("npm i class-validator class-transformer");
  sh("npm i -D @types/bcryptjs");

  sh("npx nest g module users");
  sh("npx nest g service users --no-spec");
  sh("npx nest g controller users --no-spec");
  mkdirSync(join(root, "src/users/dto"), { recursive: true });

  sh("npx nest g module auth");
  sh("npx nest g service auth --no-spec");
  sh("npx nest g controller auth --no-spec");
  mkdirSync(join(root, "src/auth"), { recursive: true });

  writeFileSync(join(root, ".env"), `PORT=3000
NODE_ENV=development

DB_HOST=${db.DB_HOST}
DB_PORT=${db.DB_PORT}
DB_USER=${db.DB_USER}
DB_PASS=${db.DB_PASS}
DB_NAME=${db.DB_NAME}

JWT_SECRET=changeme-in-prod
JWT_EXPIRES_IN=1d

SEED_ADMIN_EMAIL=${admin.ADMIN_EMAIL}
SEED_ADMIN_PASSWORD=${admin.ADMIN_PASSWORD}
SEED_ADMIN_FULLNAME=${admin.ADMIN_FULLNAME}
`);

  writeFileSync(join(root, "src/main.ts"), `import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
  const port = process.env.PORT || 3000;
  await app.listen(port);
}
bootstrap();
`);

  writeFileSync(join(root, "src/users/user.entity.ts"), `import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn } from 'typeorm';

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ unique: true })
  email: string;

  @Column()
  password: string;

  @Column({ name: 'full_name' })
  fullName: string;

  @Column({ default: true, name: 'is_active' })
  isActive: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
`);

  writeFileSync(join(root, "src/users/dto/create-user.dto.ts"), `import { IsEmail, IsNotEmpty, MinLength } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  email: string;

  @MinLength(6)
  password: string;

  @IsNotEmpty()
  fullName: string;
}
`);

  writeFileSync(join(root, "src/users/dto/login.dto.ts"), `import { IsEmail, MinLength } from 'class-validator';

export class LoginDto {
  @IsEmail()
  email: string;

  @MinLength(6)
  password: string;
}
`);

  writeFileSync(join(root, "src/users/users.service.ts"), `import { Injectable, ConflictException, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './user.entity';
import * as bcrypt from 'bcryptjs';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UsersService {
  constructor(@InjectRepository(User) private repo: Repository<User>) {}

  async create(data: CreateUserDto) {
    const exists = await this.repo.findOne({ where: { email: data.email } });
    if (exists) throw new ConflictException('Email already in use');
    const hashed = await bcrypt.hash(data.password, 10);
    const user = this.repo.create({ ...data, password: hashed });
    return this.repo.save(user);
  }

  findAll() {
    return this.repo.find({ select: ['id', 'email', 'fullName', 'isActive', 'createdAt', 'updatedAt'] });
  }

  async findOne(id: string) {
    const user = await this.repo.findOne({ where: { id } });
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  findByEmail(email: string) {
    return this.repo.findOne({ where: { email } });
  }
}
`);

  writeFileSync(join(root, "src/users/users.controller.ts"), `import { Controller, Get, UseGuards, Req } from '@nestjs/common';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  findAll() {
    return this.usersService.findAll();
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  me(@Req() req: any) {
    return req.user;
  }
}
`);

  writeFileSync(join(root, "src/users/users.module.ts"), `import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { User } from './user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UsersService],
  controllers: [UsersController],
  exports: [UsersService],
})
export class UsersModule {}
`);

  writeFileSync(join(root, "src/auth/jwt.strategy.ts"), `import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: process.env.JWT_SECRET,
    });
  }
  async validate(payload: any) {
    return { sub: payload.sub, email: payload.email, fullName: payload.fullName };
  }
}
`);

  writeFileSync(join(root, "src/auth/jwt-auth.guard.ts"), `import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {}
`);

  writeFileSync(join(root, "src/auth/auth.service.ts"), `import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcryptjs';
import { UsersService } from '../users/users.service';

@Injectable()
export class AuthService {
  constructor(private users: UsersService, private jwt: JwtService) {}

  async validateUser(email: string, pass: string) {
    const user = await this.users.findByEmail(email);
    if (!user) throw new UnauthorizedException('Invalid credentials');
    const ok = await bcrypt.compare(pass, user.password);
    if (!ok) throw new UnauthorizedException('Invalid credentials');
    return user;
  }

  async login(email: string, password: string) {
    const user = await this.validateUser(email, password);
    const payload = { sub: user.id, email: user.email, fullName: user.fullName };
    return { access_token: await this.jwt.signAsync(payload) };
  }
}
`);

  writeFileSync(join(root, "src/auth/auth.controller.ts"), `import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { LoginDto } from '../users/dto/login.dto';

@Controller('auth')
export class AuthController {
  constructor(private auth: AuthService, private users: UsersService) {}

  @Post('register')
  register(@Body() dto: CreateUserDto) {
    return this.users.create(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.auth.login(dto.email, dto.password);
  }
}
`);

  writeFileSync(join(root, "src/auth/auth.module.ts"), `import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { UsersModule } from '../users/users.module';
import { JwtStrategy } from './jwt.strategy';

@Module({
  imports: [
    UsersModule,
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: process.env.JWT_EXPIRES_IN || '1d' },
    }),
  ],
  providers: [AuthService, JwtStrategy],
  controllers: [AuthController],
})
export class AuthModule {}
`);

  writeFileSync(join(root, "src/app.module.ts"), `import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT || '5432', 10),
      username: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
      autoLoadEntities: true,
      synchronize: true,
    }),
    UsersModule,
    AuthModule,
  ],
})
export class AppModule {}
`);

  const pkgPath = join(root, "package.json");
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  pkg.scripts = pkg.scripts || {};
  pkg.scripts.seed = "ts-node src/seed.ts";
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2));

  writeFileSync(join(root, "src/seed.ts"), `import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { UsersService } from './users/users.service';

async function run() {
  const app = await NestFactory.createApplicationContext(AppModule);
  const users = app.get(UsersService);

  const email = process.env.SEED_ADMIN_EMAIL;
  const password = process.env.SEED_ADMIN_PASSWORD;
  const fullName = process.env.SEED_ADMIN_FULLNAME || 'Admin';

  if (!email || !password) {
    console.log('Seed: missing admin credentials in .env');
    await app.close();
    return;
  }

  const exists = await users.findByEmail(email);
  if (exists) {
    console.log('Seed: admin already exists ->', email);
  } else {
    await users.create({ email, password, fullName });
    console.log('Seed: admin created ->', email);
  }

  await app.close();
}
run();
`);

  writeFileSync(join(root, "README_quickstart.md"), `# Quickstart

## Run
npm install
npm run start:dev

## Seed (admin)
npm run seed

## Auth
- POST /auth/register { email, password, fullName }
- POST /auth/login { email, password } -> { access_token }

## Users
- GET /users
- GET /users/me (Bearer token)
`);
})();
