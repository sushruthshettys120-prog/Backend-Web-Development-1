# Authentication Fundamentals

Express + Prisma API implementing safe registration and login with asynchronous bcryptjs password hashing.

## Setup

Requirements: Node.js 18+ and npm.

```bash
npm install
cp .env.example .env
npm run db:push
npm test
npm start
```

On Windows PowerShell, use `Copy-Item .env.example .env` instead of `cp`.

The SQLite database is local and self-contained. Never commit `.env` or `prisma/dev.db`.

## Endpoints

### `POST /auth/register`

Request:

```json
{ "name": "Sam", "email": "sam@example.com", "password": "correct horse battery staple" }
```

Successful requests return **201** with only `id`, `name`, and `email`. Invalid input returns **400**; a duplicate normalized email returns **409**. Only a bcrypt hash is persisted.

### `POST /auth/login`

Request:

```json
{ "email": "sam@example.com", "password": "correct horse battery staple" }
```

Successful requests return **200** with only `id`, `name`, and `email`. Unknown emails and wrong passwords both return **401** with the exact same JSON error body.

## Design and security

- Routes delegate to controllers; authentication workflow lives in the service layer.
- Prisma access is isolated in repository functions.
- Emails are trimmed and lowercased for both registration and login.
- Database email uniqueness is the final duplicate guard; concurrent duplicate writes map to **409**.
- Login uses `bcrypt.compare`. An unknown email still performs a compare against a valid dummy bcrypt hash to reduce account-enumeration timing differences.
- Explicit response allowlisting prevents `password` or `passwordHash` from leaving the API.
- Unexpected errors return a controlled **500** body without raw database or bcrypt details.
- `npm test` exercises registration, hash persistence, duplicates, valid login, generic credential failures, and validation.
