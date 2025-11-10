# Guias JavaScript (12.º ano)

Este repositório junta os apontamentos usados nas aulas de Programação para o 12.º IG.

---

## Estrutura

| Pasta/ficheiro | Conteúdo                                                                                 |
| -------------- | ---------------------------------------------------------------------------------------- |
| `JavaScript/`  | 17 capítulos em Markdown cobrindo o percurso completo: fundamentos → browser/intermédio. |
| `Node/`        | Guia completo de Node.js + Express com foco em APIs REST, camadas e troubleshooting.     |
| `React/`       | Materiais introdutórios de React (em evolução).                                          |

> Todos os capítulos de JavaScript seguem o mesmo formato: título, objetivo, secções numeradas, exemplos comentados e desafios no fim.

---

## JavaScript — Capítulos

### Fundamentos (01‑12)

1. [01 — Variáveis e Tipos](JavaScript/01-Variaveis-Tipos.md)
2. [02 — Input/Output Básico](JavaScript/02-IO-Basico.md)
3. [03 — Operadores Essenciais](JavaScript/03-Operadores.md)
4. [04 — Strings](JavaScript/04-Strings.md)
5. [05 — Estruturas de Controlo](JavaScript/05-Controlo-Fluxo.md)
6. [06 — Ciclos](JavaScript/06-Ciclos.md)
7. [07 — Arrays](JavaScript/07-Arrays.md)
8. [08 — Objetos e `this`](JavaScript/08-Objetos-e-this.md)
9. [09 — Exceções](JavaScript/09-Excecoes.md)
10. [10 — Funções](JavaScript/10-Funcoes.md)
11. [11 — Funções de Alto Nível em Arrays](JavaScript/11-Arrays-HighOrder.md)
12. [12 — Módulos ES](JavaScript/12-Modulos-ES.md)

### Intermédio / Browser (13‑17)

13. [13 — Classes e OOP](JavaScript/13-POO-Classes.md)
14. [14 — Assíncrono e Event Loop](JavaScript/14-Assincrono-EventLoop.md)
15. [15 — DOM Básico](JavaScript/15-DOM-Basico.md)
16. [16 — Fetch / AJAX](JavaScript/16-Fetch-AJAX.md)
17. [17 — Outros Tópicos Úteis](JavaScript/17-Outros-Topicos.md)

Cada ficheiro tem exemplos prontos a colar no DevTools/Node e termina com desafios curtos para garantir prática imediata.

---

## Como estudar

1. **Percurso recomendado**
    - Sessão 1: capítulos 01‑04 (variáveis, operadores, strings)
    - Sessão 2: 05‑07 (controlo, ciclos, arrays)
    - Sessão 3: 08‑10 (objetos, exceções, funções)
    - Sessão 4: 11‑12 (HOFs e módulos)
    - Sessões 5‑6: 13‑17 (OOP, async, DOM, Fetch, extras)
2. **Método**
    - Lê o capítulo rapidamente.
    - Executa os snippets na consola do browser ou em Node (`node ficheiro.js`).
    - Resolve os desafios antes de avançar.

---

## Ambiente sugerido

-   **Browser (DevTools → Console)** para testar snippets de forma rápida ou usar JSFiddle / JS Playground.
-   **Node.js** para scripts standalone: `node exemplo.js`.
-   Usa `"use strict"` ou `<script type="module">` para manter o comportamento moderno.

---

## React

A pasta `React/` contém guias de introdução à framework (setup, componentes, estado). Estes materiais seguem a mesma filosofia: capítulos em Markdown focados em exemplos e desafios.

---

## Node.js — Guias didáticos

Ordem sugerida:

1. [00 — Introdução ao Node.js](Node/00_introducao_ao_node.md): história, event loop, arquitetura cliente-servidor, APIs REST e glossário essencial.
2. [00 — Setup rápido de projeto](Node/00_setup_projeto.md): instalação, dependências e estrutura base (`src/`, scripts npm e boas práticas de equipa).
3. [01 — Módulos em Node](Node/01_modulos_node.md): diferença entre ES Modules e CommonJS, imports relativos e top-level `await`.
4. [02 — Node core útil](Node/02_node_core.md): `path`, `fs/promises`, `process`, `os`, `events`, `crypto` e quando usar cada um.
5. [03 — HTTP nativo vs Express](Node/03_http_vs_express.md) e [03_Guia_js_Node_Express.js](Node/03_Guia_js_Node_Express.js): panorama completo de HTTP, glossário de camadas e guia passo a passo para montar APIs.
6. [04 — Express base](Node/04_express_basico.md): middlewares globais, health checks e separação `app`/`server`.
7. [05 — Estrutura MVC leve](Node/05_estrutura_mvc.md): responsabilidades de routes, controllers, services e repositories.
8. [06 — Rotas, controladores e validação](Node/06_rotas_controladores_validacao.md): routers Express, verbos HTTP e validação com Zod.
9. [07 — Erros e asyncHandler](Node/07_erros_e_async_handler.md): gestão centralizada de 404/500 e criação de erros personalizados.
10. [08 — Persistência em JSON](Node/08_persistencia_json.md): ler/escrever ficheiros com segurança antes de migrar para uma BD.
11. [09 — Segurança e logging](Node/09_seguranca_logging.md): CORS, Helmet, rate-limit, compressão e notas sobre autenticação.
12. [10 — Config e 12-Factor](Node/10_config_e_12factor.md): `.env`, módulos de configuração e boas práticas.
13. [11 — Testes com Supertest/Vitest](Node/11_testes_supertest_vitest.md): motivos para testar e exemplos prontos.
14. [12 — Views com EJS](Node/12_ejs_views.md): SSR opcional para prototipar interfaces simples.
15. [13 — Troubleshooting](Node/13_troubleshooting.md): erros comuns, estratégia de depuração e ferramentas úteis.

Todos os ficheiros de `Node/` terminam com um `## Changelog` para documentar evoluções futuras.
