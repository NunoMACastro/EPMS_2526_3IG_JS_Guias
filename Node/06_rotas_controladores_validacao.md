# 06) Rotas, controladores e validação (Zod opcional)

## Router

```js
// src/routes/todos.router.js
import { Router } from "express";
import * as ctrl from "../controllers/todos.controller.js";
import { validate } from "../middlewares/validate.js";
import { todoCreateSchema, todoUpdateSchema, idParamSchema } from "../schemas/todo.schemas.js";

const r = Router();

r.get("/", ctrl.listar);
r.get("/:id", validate({ params: idParamSchema }), ctrl.obter);
r.post("/", validate({ body: todoCreateSchema }), ctrl.criar);
r.patch("/:id", validate({ params: idParamSchema, body: todoUpdateSchema }), ctrl.atualizar);
r.delete("/:id", validate({ params: idParamSchema }), ctrl.remover);

export default r;
```

## Controller

```js
// src/controllers/todos.controller.js
import * as service from "../services/todos.service.js";
import { asyncHandler } from "../utils/asyncHandler.js";

export const listar = asyncHandler(async (_req, res) => {
  const itens = await service.listar();
  res.json(itens);
});

export const obter = asyncHandler(async (req, res) => {
  const item = await service.obter(req.params.id);
  if (!item) return res.status(404).json({ error: "Todo não encontrado" });
  res.json(item);
});

export const criar = asyncHandler(async (req, res) => {
  const novo = await service.criar(req.body);
  res.status(201).json(novo);
});

export const atualizar = asyncHandler(async (req, res) => {
  const item = await service.atualizar(req.params.id, req.body);
  if (!item) return res.status(404).json({ error: "Todo não encontrado" });
  res.json(item);
});

export const remover = asyncHandler(async (req, res) => {
  const ok = await service.remover(req.params.id);
  if (!ok) return res.status(404).json({ error: "Todo não encontrado" });
  res.status(204).send();
});
```

## Validação (opcional com Zod)

```js
// src/middlewares/validate.js
import { ZodError } from "zod";
export function validate(schemas = {}) {
  return (req, res, next) => {
    try {
      if (schemas.params) req.params = schemas.params.parse(req.params);
      if (schemas.query) req.query = schemas.query.parse(req.query);
      if (schemas.body) req.body = schemas.body.parse(req.body);
      next();
    } catch (e) {
      if (e instanceof ZodError) {
        return res.status(400).json({ error: "Validação falhou", details: e.issues });
      }
      next(e);
    }
  };
}
```

```js
// src/schemas/todo.schemas.js
import { z } from "zod";

export const idParamSchema = z.object({
  id: z.string().uuid("id precisa ser UUID válido"),
});

export const todoCreateSchema = z.object({
  titulo: z.string().min(1),
  concluido: z.boolean().optional().default(false),
});

export const todoUpdateSchema = todoCreateSchema.partial();
```

## Porque dividir assim?

-   **Router** apenas liga URLs a funções. Quanto menos lógica tiver, mais fácil é testar cada parte.
-   **Controller** conhece `req` e `res`. É aqui que transformas dados de entrada e decides códigos HTTP (201, 404, 204…).
-   **Service** (ver ficheiro 08) trata das regras de negócio e chama o repositório. O controller não sabe onde os dados estão guardados.

## Verbos HTTP (relembra a turma)

-   `GET /todos` → ler.
-   `GET /todos/:id` → ler um recurso específico.
-   `POST /todos` → criar.
-   `PATCH /todos/:id` → alterar parcialmente.
-   `DELETE /todos/:id` → remover.

Mantém o plural para coleções e usa `:` para parâmetros dinâmicos (`:id`).

## Validação com e sem Zod

-   **Sem Zod**: escreves condicionais (`if (!req.body.titulo) ...`). Funciona mas torna-se repetitivo.
-   **Com Zod**: defines o formato apenas uma vez. Se falhar, devolve lista de erros com mensagens claras.
-   Podes também validar `query` (filtros) e `headers` se precisares de tokens.

## Dica de UX na API

-   Quando um recurso não é encontrado, devolve `{ error: "..." }` e um `status 404`.
-   Ao criar algo com sucesso usa `201` e devolve o objeto completo (para mostrar o ID gerado).
-   Um `DELETE` bem-sucedido pode devolver `204 No Content` — não precisa de body.

## Exercício rápido (para os alunos)

1. Adiciona campo `descricao` opcional no `todoCreateSchema`.
2. Atualiza o controller para aceitar o novo campo.
3. Testa com o Thunder Client/Postman e verifica o formato da resposta.

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Explicadas as responsabilidades de router/controller/service e reforçado o uso de verbos HTTP.
    -   Incluída análise sobre validação com e sem Zod e secção de changelog.
