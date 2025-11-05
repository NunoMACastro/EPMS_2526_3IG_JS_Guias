# Guias de JavaScript — 12.º IG

Este repositório reúne **apontamentos práticos** para as aulas de Programação (JavaScript) e um guia de arranque para **Node.js + Express**. Os ficheiros são pensados para leitura rápida e copy/paste de pequenos trechos quando necessário.

## Conteúdos

### 01_Guia_js_Basico.js

Guia de **introdução ao JavaScript no browser**. Cobre, de forma direta:

-   Variáveis (`let`, `const`) e tipos primitivos
-   Operadores e regras de truthy/falsy
-   Strings e _template literals_
-   Estruturas de controlo (`if`, `switch`) e repetição (`for`, `while`, `for...of`)
-   Arrays e métodos essenciais (map, filter, reduce, …)
-   Objetos e noções de `this`
-   Exceções (try/catch/throw)
-   Funções (declaração, expressão, arrow, parâmetros, closures)

### 02_Guia_js_Intermedio.js

Guia **intermédio** para quem já domina o básico. Inclui:

-   **ES Modules** (import/export, top‑level await)
-   **Classes/OOP** modernas (constructor, getters/setters, `#privado`, `static`, herança)
-   **Assíncrono** (Promises, `async/await`, microtasks vs tasks)
-   **DOM** (seletores, criação/injeção, classes, eventos, delegação, formulários)
-   **Fetch/AJAX** (GET/POST JSON, erros, `AbortController`/timeout, upload com `FormData`)
-   Extras úteis no browser: `URLSearchParams`, History API, `IntersectionObserver`, `Intl`, notas rápidas de A11y/Segurança/Performance

### 03_Guia_js_Node_Express.js

Guia de **Node.js + Express** para criar APIs simples. Traz:

-   Organização básica do projeto e _snippets_ de app/servidor
-   Middlewares comuns, rotas e respostas
-   Separação sugerida: routes → controllers → services → repositories
-   Persistência didática em ficheiro JSON (sem base de dados)
-   Validação opcional com Zod e tratamento central de erros
-   Secção opcional de **EJS** (templates no servidor) para páginas simples
