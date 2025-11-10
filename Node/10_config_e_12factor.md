# 10) Variáveis de ambiente e 12-Factor

## .env (exemplo)

```
PORT=3000
NODE_ENV=development
LOG_LEVEL=debug
CORS_ORIGIN=http://localhost:5173
CORS_CREDENTIALS=false
```

No código:
```js
const PORT = Number(process.env.PORT || 3000);
```

## Módulo de config

```js
// src/utils/config.js
function reqEnv(name, def = undefined) {
  const v = process.env[name] ?? def;
  if (v === undefined) throw new Error(`Falta variável de ambiente: ${name}`);
  return v;
}

export const config = Object.freeze({
  env: process.env.NODE_ENV || "development",
  port: Number(process.env.PORT || 3000),
  corsOrigin: process.env.CORS_ORIGIN || "*",
  corsCredentials: process.env.CORS_CREDENTIALS === "true",
});
```

## Boas práticas 12-Factor
- Nada de hardcode de segredos e URLs.
- Config por ambiente (.env ou variáveis da plataforma).
- Logs como streams (evitar console espalhado).

## Porque usar variáveis de ambiente?

-   Os servidores de produção (Render, Railway, Fly.io) permitem definir valores por ambiente. Assim não precisas de editar código para alterar a porta ou a ligação à BD.
-   Facilita partilhar o projeto: cada colega cria o seu `.env` com as próprias chaves e ninguém corre risco de expor segredos no Git.

## Estratégia didática

1. Cria um `.env.example` com as chaves necessárias (sem valores reais). Isto serve como checklist para novos alunos.
2. Explica que `process.env` só aceita strings. Quando precisares de número/boolean usa `Number(...)` ou `=== "true"`.
3. Centraliza a leitura num módulo `config` e importa em todo o lado. Se amanhã mudares o nome da variável, só precisas de tocar aqui.

## Exercício

-   Adiciona `API_BASE_URL` ao `.env`.
-   Atualiza o módulo `config` para expor `apiBaseUrl`.
-   Usa o valor no serviço que fala com APIs externas (por exemplo, para enviar emails).

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Explicadas as vantagens de `.env`, criado plano de aula e exercício guiado.
    -   Adicionada secção de changelog.
