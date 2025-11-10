# 12) Views com EJS (SSR opcional)

## O que é EJS
Motor de templates para gerar HTML no servidor:
- <% código %>
- <%= expr_escapada %> (seguro por defeito)
- <%- expr_sem_escape %> (apenas para HTML de confiança)

## Instalar
```bash
npm i ejs express-ejs-layouts
```

## Estrutura
```
src/
  views/
    layout.ejs
    partials/
      head.ejs
      header.ejs
      footer.ejs
    pages/
      home.ejs
      todos/
        index.ejs
        new.ejs
```

## Configurar na app

```js
// excerto de src/app.js
import path from "node:path";
import { fileURLToPath } from "node:url";
import expressLayouts from "express-ejs-layouts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(expressLayouts);
app.set("layout", "layout");

app.use("/static", express.static(path.join(__dirname, "public")));

app.locals.appName = "Minha App";
app.locals.fmtData = (ts) =>
  new Intl.DateTimeFormat("pt-PT", { dateStyle: "medium", timeStyle: "short" }).format(ts);
```

## Router de páginas

```js
// src/routes/pages.router.js
import { Router } from "express";
import * as todos from "../services/todos.service.js";

const pages = Router();

pages.get("/", (_req, res) => {
  res.render("pages/home", { titulo: "Bem-vindo", agora: Date.now() });
});

pages.get("/todos", async (_req, res, next) => {
  try {
    const lista = await todos.listar();
    res.render("pages/todos/index", { titulo: "Lista de Tarefas", lista });
  } catch (e) { next(e); }
});

pages.get("/todos/new", (_req, res) => {
  res.render("pages/todos/new", { titulo: "Novo Todo", errors: [], values: {} });
});

pages.post("/todos", async (req, res, next) => {
  try {
    const { titulo } = req.body;
    if (!titulo?.trim()) {
      return res.status(400).render("pages/todos/new", {
        titulo: "Novo Todo",
        errors: [{ message: "Título é obrigatório" }],
        values: { titulo },
      });
    }
    await todos.criar({ titulo });
    res.redirect("/todos");
  } catch (e) { next(e); }
});

export default pages;
```

Dicas rápidas:
1. Usa <%= ... %> por defeito (escapado).
2. Se precisares de embutir JSON em script, evita fechar acidentalmente a tag:
   ```ejs
   <script>
     const DATA = <%- JSON.stringify(obj).replace(/</g, "\u003c") %>;
   </script>
   ```
3. Em produção, ativa cache de views com app.set("view cache", true). O Express ativa por defeito quando NODE_ENV é production.

## Quando usar SSR com EJS?

-   Projetos pedagógicos onde queres mostrar uma lista sem construir logo um front-end React.
-   Páginas públicas (landing page, formulário) que beneficiam de SEO imediato.
-   Prototipagem rápida: podes iterar no HTML diretamente e reaproveitar o mesmo serviço/rotas da API.

## Fluxo de dados

`router → service → res.render(view, dados) → EJS → HTML final`.

Explica que o `res.render` recebe um objeto com dados e a view transforma essas variáveis em HTML final antes de ser enviado ao browser.

## Formularios e CSRF

-   Quando usares `method="post"`, ativa `express.urlencoded` no `app.js`.
-   Para aulas introdutórias, podes manter o formulário simples. Em produção, adiciona tokens CSRF (biblioteca `csurf`) para evitar submissões maliciosas.

## Estilos e assets

-   Coloca CSS/JS na pasta `public/` e expõe via `app.use("/static", express.static(...))`.
-   Em EJS, referencia com `<link rel="stylesheet" href="/static/styles.css">`.

## Exercício

1. Adiciona botão “Marcar como concluído” na view `todos/index`.
2. Cria rota `POST /todos/:id/complete` que usa o service para atualizar o registo.
3. Atualiza a view para mostrar a nova informação.

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Acrescentadas explicações sobre quando usar SSR, fluxo de dados, formulários e exercícios.
    -   Incluída secção de changelog.
