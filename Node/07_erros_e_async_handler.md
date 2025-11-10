# 07) Erros (404 e 500) e asyncHandler

## Middlewares de erro

```js
// src/middlewares/errors.js
export function notFound(_req, res, _next) {
  res.status(404).json({ error: "Rota não encontrada" });
}

export function errorHandler(err, _req, res, _next) {
  const status = err.status || 500;
  const payload = { error: err.message || "Erro interno" };
  if (process.env.NODE_ENV !== "production") payload.stack = err.stack;
  res.status(status).json(payload);
}
```

## asyncHandler para evitar try-catch repetido

```js
// src/utils/asyncHandler.js
export const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
```

## Como funciona a cadeia de middlewares?

1. O Express executa as rotas e middlewares pela ordem em que foram registados.
2. Quando nada corresponde ao pedido, o Express avança até encontrar um middleware com **quatro parâmetros** (`err, req, res, next`). Esse é o handler de erro.
3. `notFound` deve vir antes do `errorHandler` para apanhar rotas inexistentes.
4. `errorHandler` recebe qualquer erro que aconteceu em rotas async/await desde que usemos o `asyncHandler`.

## Porque usar `asyncHandler`?

-   Em funções `async`, um erro lança uma `Promise` rejeitada. Sem `asyncHandler`, terias de envolver *todas* as rotas em `try/catch` e chamar manualmente `next(err)`.
-   `asyncHandler` embrulha a função e garante que qualquer rejeição cai automaticamente no middleware de erro.

## Criar erros personalizados

```js
export class HttpError extends Error {
  constructor(message, status = 500) {
    super(message);
    this.status = status;
  }
}

throw new HttpError("Todo não encontrado", 404);
```

No `errorHandler` podes ler `err.status` para devolver códigos corretos. Ensina os alunos a nunca devolver dados sensíveis (stack traces) em produção.

## Boas práticas didáticas

-   Loga os erros com `console.error` em desenvolvimento para mostrar onde falhou.
-   Em produção, envia apenas mensagens genéricas (`"Erro interno"`).
-   Se o erro for esperado (ex.: validação), devolve 400/422 com detalhes — o front consegue reagir melhor.

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Adicionados fluxos explicativos sobre middlewares, criação de erros personalizados e boas práticas.
    -   Criada secção de changelog.
