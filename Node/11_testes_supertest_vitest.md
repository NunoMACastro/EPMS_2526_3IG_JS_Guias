# 11) Testes com Supertest e Vitest

## Instalar
```bash
npm i -D supertest vitest
```

## Teste de exemplo

```js
// tests/health.test.js
import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "../src/app.js";

describe("health", () => {
  it("GET /api/health devolve ok", async () => {
    const res = await request(app).get("/api/health");
    expect(res.status).toBe(200);
    expect(res.body.status).toBe("ok");
  });
});
```

## Scripts úteis
- test: vitest --run
- test:watch: vitest

## Porque testar APIs?

-   Garantem que endpoints continuam a funcionar mesmo depois de refatorares controllers/services.
-   Servem como documentação viva: outro colega pode ler o teste e perceber como chamar o endpoint.
-   Incentivam-te a separar `app` de `server`, já que o Supertest importa apenas o `app`.

## Estrutura típica de testes

```
tests/
  health.test.js
  todos.test.js
```

-   Usa `describe` para agrupar endpoints ou contextos.
-   Usa `beforeEach` para preparar dados (por exemplo, criar ficheiros temporários).
-   Limpa o ambiente com `afterEach`/`afterAll` (remover ficheiros, restaurar mocks).

## Exemplo adicional: criar todo

```js
import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "../src/app.js";

describe("todos", () => {
  it("cria um todo válido", async () => {
    const res = await request(app).post("/api/v1/todos").send({ titulo: "Estudar Node" });
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ titulo: "Estudar Node", concluido: false });
  });
});
```

## Dicas para o professor

-   Usa `npm run test:watch` durante a aula: os alunos vêm os testes a disparar sempre que editam um ficheiro.
-   Começa com apenas um teste (health) para mostrar a mecânica e depois pede que construam o teste de criação e listagem.
-   Para acelerar, podes mockar o repository com `vi.mock("../src/repositories/todos.repo.file.js", () => ({ ... }))`.

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Acrescentadas razões pedagógicas para testar, estrutura recomendada e novo exemplo de teste para criação de todos.
    -   Incluída secção de changelog.
