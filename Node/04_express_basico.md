# 04) Express - app base, middlewares e estáticos

## src/app.js

```js
/**
 * Cria e configura a aplicação Express com middlewares globais.
 */
import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import compression from "compression";
import rateLimit from "express-rate-limit";

import path from "node:path";
import { fileURLToPath } from "node:url";

import todosRouter from "./routes/todos.router.js";
import { notFound, errorHandler } from "./middlewares/errors.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const app = express();

// Segurança e utilitários
app.use(helmet());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    credentials: Boolean(process.env.CORS_CREDENTIALS === "true"),
  })
);
// Nota: se usares credentials=true, não uses origin="*". Define o domínio do front.
app.use(compression());
app.use(morgan("dev"));

// Rate limit básico
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use(limiter);

// Body parsers
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

// Estáticos
app.use("/static", express.static(path.join(__dirname, "public")));

// Healthcheck
app.get("/api/health", (_req, res) => res.json({ status: "ok", ts: Date.now() }));

// API
app.use("/api/v1/todos", todosRouter);

// 404 e Erros
app.use(notFound);
app.use(errorHandler);
```

## src/server.js

```js
/**
 * Ponto de arranque do servidor HTTP.
 */
import { app } from "./app.js";

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";

app.listen(PORT, HOST, () => {
  console.log(`API a escutar em http://${HOST}:${PORT}`);
});
```

## Explicação passo a passo

-   `helmet`, `cors`, `compression`, `morgan` e `rateLimit` são **middlewares globais**. Eles correm para **todas** as rotas, na ordem em que aparecem. Por isso, coloca primeiro os que protegem (Helmet, CORS), depois utilitários (logging, compressão) e só então o teu código.
-   `express.json` e `express.urlencoded` leem o corpo do pedido e colocam o resultado em `req.body`. Sem estes middlewares um `POST` com JSON chega como texto cru e terias de fazer `JSON.parse` à mão.
-   Os ficheiros de `/public` ficam expostos através do `express.static`. O primeiro argumento (`/static`) é o prefixo da rota — podes alterar para `/assets` se fizer mais sentido.
-   O endpoint `/api/health` atua como termómetro: podes usá-lo em monitores (UptimeRobot, Render, Railway) para confirmar que o servidor está vivo.

## Porque separar `app` de `server`?

-   Durante os testes com Supertest importas apenas `app`. Isto evita bugs de “porta já ocupada” e torna mais rápido usar `vitest --run`.
-   No `server.js` podes ler variáveis de ambiente e escolher host/porta diferentes consoante o contexto (local, produção, container).

## Ordem final recomendada

1. Configuração (locals, view engine, static).
2. Segurança e utilitários.
3. Parsers de body.
4. Rotas que servem páginas (se existir SSR).
5. Rotas da API (versão em prefixo `/api/v1`).
6. Middlewares de 404 e de erro.

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Adicionadas explicações sobre a ordem dos middlewares, função de cada bloco e separação app/server.
    -   Criada secção de changelog.
