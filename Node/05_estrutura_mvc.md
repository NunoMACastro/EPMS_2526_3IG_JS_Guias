# 05) Estrutura de pastas (MVC leve e camadas)

```
src/
  app.js
  server.js
  routes/
    todos.router.js
  controllers/
    todos.controller.js
  services/
    todos.service.js
  repositories/
    todos.repo.file.js
  middlewares/
    errors.js
    validate.js      # opcional (Zod)
  schemas/
    todo.schemas.js
  utils/
    asyncHandler.js
    config.js
  data/
    todos.json
  public/
```

Responsabilidades:
- Route: recebe req e res e chama o controller.
- Controller: valida input, chama service e formata resposta.
- Service: regras de negócio.
- Repository: detalhe de acesso a dados (ficheiro ou base de dados).

## Como explicar cada camada aos alunos

-   **Routes** ≈ rececionista. Verifica o endereço pedido e chama a pessoa certa.
-   **Controllers** ≈ chefe de equipa. Recebe os dados, valida-os e chama os serviços necessários.
-   **Services** ≈ especialistas. Contêm as regras “se a tarefa já existe, lança erro”, etc. Aqui não existem detalhes de HTTP.
-   **Repositories** ≈ base de dados/ficheiro. Sabem como guardar e ler informação. Se amanhã trocarmos JSON por MongoDB, só esta camada muda.
-   **Middlewares** ≈ filtros automáticos. Podem bloquear pedidos inválidos antes de chegarem aos controllers.

## Boas práticas extra

1. **Um ficheiro, um propósito**: se o controller começa a ficar gigante, divide-o por recurso (`users.controller.js`, `todos.controller.js`).
2. **Criar índices com `index.js`**: podes expor múltiplos routers a partir de `routes/index.js`, mas evita esconder ficheiros — para iniciantes é útil ver o caminho completo.
3. **Nomear pelas ações**: `todos.service.js` deve conter funções como `listar`, `obter`, `criar`… Usa verbos no infinitivo para manter consistência.
4. **Data flow claro**: `req -> controller -> service -> repository -> service -> controller -> res`. Mostra este fluxo num quadro para fixar.

## Checklist antes de criar uma nova funcionalidade

-   Precisas de rota nova? Atualiza `routes/`.
-   A lógica depende de regras de negócio? Vai para `services/`.
-   Vais persistir algo diferente? Cria um novo ficheiro em `repositories/`.
-   Vais validar dados? Ou atualiza o schema Zod ou cria `middlewares/validate`.
-   Vais reutilizar funções pequenas? Coloca em `utils/`.

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Adicionadas analogias para explicar as camadas e checklist para novas funcionalidades.
    -   Incluída esta secção de changelog.
