# 00) Setup rápido de projeto

> Se ainda não leste o capítulo [Introdução ao Node.js](./00_introducao_ao_node.md), começa por aí para perceberes o contexto e a arquitetura do runtime.

## 1) Criar projeto e instalar dependências

```bash
mkdir api-aula && cd api-aula
npm init -y
npm pkg set type=module
npm i express cors helmet morgan compression
npm i -D nodemon
npm i zod            # opcional (validação)
npm i -D prettier eslint eslint-config-prettier eslint-plugin-import
```

-   **Porque estes comandos?**
    -   `npm init -y` cria rapidamente o `package.json`, o “cartão de cidadão” do projeto (nome, scripts, dependências).
    -   `npm pkg set type=module` diz ao Node para assumir ES Modules (`import/export`) em vez de `require`. Isto alinha o servidor com o JavaScript moderno ensinado no browser.
    -   `npm i` instala dependências que existirão também em produção (Express, CORS, etc.). `npm i -D` instala ferramentas apenas para desenvolvimento (lint, formatação, testes).
-   **Para que serve cada pacote base?**
    -   `express`: motor HTTP de alto nível que trata rotas e middlewares.
    -   `cors`: permite controlar que aplicações front-end podem falar com a tua API.
    -   `helmet`: adiciona cabeçalhos de segurança automaticamente (Content-Security-Policy, X-Frame-Options…).
    -   `morgan`: logger simples de requests (ótimo para aulas).
    -   `compression`: ativa gzip/brotli para enviar respostas mais leves.
    -   `nodemon`: reinicia o servidor sempre que guardas um ficheiro em desenvolvimento.
    -   `zod`: biblioteca opinativa para validar dados (evita ifs gigantes).
    -   `prettier` e `eslint`: robôs que alinham estilo e pegam em más práticas automaticamente.

## 2) Scripts em package.json

```json
{
    "name": "api-aula",
    "type": "module",
    "scripts": {
        "dev": "nodemon --env-file .env --watch src --ext js,mjs,cjs --exec \"node src/server.js\"",
        "start": "node src/server.js",
        "lint": "eslint .",
        "format": "prettier -w .",
        "test": "vitest --run",
        "test:watch": "vitest"
    }
}
```

## 3) .gitignore

```
node_modules
.env
coverage
dist
```

## 4) Pastas base

```
src/
  app.js
  server.js
  routes/
  controllers/
  services/
  repositories/
  middlewares/
  schemas/
  utils/
  data/
  public/
```

Dica: cria também .editorconfig, eslint.config.js e prettier.config.cjs para uniformizar o estilo.

## 5) Ficheiros iniciais

-   Cria src/app.js e src/server.js como em 04_express_basico.md.
-   Cria routes/controllers/services/repositories como em 06 a 08.

### Porque é útil esta estrutura?

-   **`src/app.js`**: onde montas o Express. Fica responsável por configurar middlewares, rotas e erros. Ao separar do `server.js` consegues testar a aplicação sem arrancar um servidor real (Supertest importa só o `app`).
-   **`routes/` → `controllers/` → `services/` → `repositories/`**: camadas claras evitam misturar validação com acesso a ficheiros/BD. Quando chegares a bases de dados reais, só precisas de trocar a pasta `repositories/`.
-   **`middlewares/`**: funções que correm _antes_ ou _depois_ das rotas. Organizar aqui evita duplicação (autenticação, validação, etc.).
-   **`schemas/`**: definem o “contrato” dos dados (por exemplo, como deve ser um `todo`). Com o Zod consegues validar e gerar mensagens de erro consistentes para os alunos.
-   **`utils/`**: pequenas funções reutilizáveis, como `asyncHandler` para apanhar erros de funções assíncronas sem encher o código com `try/catch`.
-   **`data/`**: onde vivemos com JSON durante a fase didática. Em projetos maiores esta pasta dá lugar a uma base de dados real (MongoDB, PostgreSQL, etc.).
-   **`public/`**: ficheiros estáticos (CSS, imagens) caso queiras mostrar uma UI simples sem recorrer logo a React.

### Checklist antes de começar a programar

1. **Node atualizado**: usa a LTS >= 18 para ter `fetch`, `crypto.randomUUID` e outras APIs modernas sem polyfills.
2. **`.env` criado**: define `PORT`, `NODE_ENV` e qualquer segredo temporário. Nunca comites o ficheiro – o `.gitignore` já o protege.
3. **VS Code com ESLint/Prettier**: a formatação automática reduz 80% das discussões de estilo.
4. **Scripts testados**: corre `npm run dev` e `npm run lint` uma vez para confirmar que tudo está configurado.
5. **Explica ao aluno**: reforça que este setup é o “esqueleto” que reutilizam em qualquer API Express básica.

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Adicionadas explicações teóricas sobre cada comando, dependência e sobre a estrutura de pastas.
    -   Incluído checklist pedagógico e criada a secção de changelog para acompanhar futuras alterações.
    -   Referência cruzada para o novo capítulo de introdução ao Node.
