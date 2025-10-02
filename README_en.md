# 🚀 NestJS Generator (PostgreSQL · TypeORM · Users · JWT Auth)

A one-shot generator script that scaffolds a **NestJS** API with:
- **TypeORM + PostgreSQL** connection via `.env`
- **Users** module (entity/service/controller/DTOs)
- **JWT Auth** (register + login, `JwtStrategy`, guard)
- **ValidationPipe** enabled globally
- **Seed** script for an initial admin user

> Script file: `setup-nestjs-pro.mjs`

## 🧰 Prerequisites
- Node.js 18+
- PostgreSQL running and reachable

## 🏁 Initialize the project
```bash
# create a new API in the 'my-nest-api' folder
node setup-nestjs-pro.mjs my-nest-api
```

The script will ask for:
- DB credentials (`DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME`)
- Initial admin (`ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_FULLNAME`)

## ▶️ Run
```bash
cd my-nest-api
npm install   # if the CLI didn't already install
npm run start:dev
```

## 🌱 Seed initial admin (optional)
```bash
npm run seed
```
Uses the `SEED_*` values written in `.env` by the generator.

## 🔐 Endpoints
- `POST /auth/register` → `{ email, password, fullName }`
- `POST /auth/login` → `{ email, password }` ⇒ `{ access_token }`
- `GET /users`
- `GET /users/me` (requires `Authorization: Bearer <token>`)

## 🗂 Project structure (excerpt)
```
src/
├─ app.module.ts
├─ main.ts
├─ auth/
│  ├─ auth.controller.ts
│  ├─ auth.module.ts
│  ├─ auth.service.ts
│  ├─ jwt-auth.guard.ts
│  └─ jwt.strategy.ts
├─ users/
│  ├─ dto/
│  │  ├─ create-user.dto.ts
│  │  └─ login.dto.ts
│  ├─ user.entity.ts
│  ├─ users.controller.ts
│  └─ users.service.ts
└─ seed.ts
```

## ⚙️ Environment variables (created by the script)
```dotenv
PORT=3000
NODE_ENV=development

DB_HOST=
DB_PORT=
DB_USER=
DB_PASS=
DB_NAME=

JWT_SECRET=
JWT_EXPIRES_IN=1d

SEED_ADMIN_EMAIL=
SEED_ADMIN_PASSWORD=
SEED_ADMIN_FULLNAME=
```

> Keep `.env` out of version control. Commit an `.env.example` with keys only.

## 🧪 Notes
- `synchronize: true` is enabled for **development only**. Use migrations in production.
- You can add Swagger later in `main.ts` if you want `/docs`.
