# 🚀 Generador NestJS (PostgreSQL · TypeORM · Users · JWT Auth)

Script “one-shot” que crea una API **NestJS** con:
- Conexión **TypeORM + PostgreSQL** vía `.env`
- Módulo **Users** (entity/service/controller/DTOs)
- **Auth con JWT** (register + login, `JwtStrategy`, guard)
- **ValidationPipe** global
- **Seed** para crear un usuario admin inicial

> Archivo del script: `setup-nestjs-pro.mjs`

## 🧰 Requisitos
- Node.js 18+
- PostgreSQL en ejecución y accesible

## 🏁 Inicializar el proyecto
```bash
# crea una nueva API en la carpeta 'my-nest-api'
node setup-nestjs-pro.mjs my-nest-api
```

El script te va a pedir:
- Credenciales de DB (`DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASS`, `DB_NAME`)
- Admin inicial (`ADMIN_EMAIL`, `ADMIN_PASSWORD`, `ADMIN_FULLNAME`)

## ▶️ Ejecutar
```bash
cd my-nest-api
npm install   # si el CLI no instaló automáticamente
npm run start:dev
```

## 🌱 Seed de admin (opcional)
```bash
npm run seed
```
Usa los valores `SEED_*` que el generador dejó en `.env`.

## 🔐 Endpoints
- `POST /auth/register` → `{ email, password, fullName }`
- `POST /auth/login` → `{ email, password }` ⇒ `{ access_token }`
- `GET /users`
- `GET /users/me` (requiere `Authorization: Bearer <token>`)

## 🗂 Estructura (extracto)
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

## ⚙️ Variables de entorno (creadas por el script)
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

> No subas `.env` al repo. Subí un `.env.example` solo con las claves.

## 🧪 Notas
- `synchronize: true` está habilitado **solo para desarrollo**. En producción usá migraciones.
- Podés sumar Swagger luego en `main.ts` para exponer `/docs`.
