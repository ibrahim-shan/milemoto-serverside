# MileMoto Server — Local setup (Node + Express + MySQL)

## Prereqs
- Node.js 20+
- MySQL 8+ (or MariaDB). With XAMPP: start **MySQL**.
- Create DB: `CREATE DATABASE milemoto CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;`

## Setup
1) `cp .env.example .env` and set your local credentials.
2) `npm i`
3) `npm run migrate`   # applies `migrations/*.sql`
4) `npm run dev`       # http://localhost:4000

Health check: `GET /api/health` → `{ ok: true }`

Notes:
- Prices are stored as `price_minor` in cents. Currency fixed to USD in app layer.
- To build and run: `npm run build && npm start`
