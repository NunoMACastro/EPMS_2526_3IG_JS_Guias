# 00) Introdução ao Node.js

> **Objetivo**: entender o que é o Node.js, a sua história, arquitetura interna, casos de uso ideais, quando evitar, como instalar e manter atualizado, e os primeiros passos para correr JavaScript fora do browser.

## 1) O que é o Node.js?

-   **Runtime JavaScript fora do browser.** Em vez de correr JS apenas no Chrome/Firefox, o Node usa o motor V8 (o mesmo do Chrome) para executar código diretamente no sistema operativo.
-   **Single-threaded com I/O não bloqueante.** Existe um único _thread_ principal a correr JavaScript, mas operações de disco/rede são delegadas a um _pool_ interno (libuv). Isto permite atender muitos pedidos em simultâneo sem criar uma thread por pedido.
-   **Ecossistema npm.** Com mais de 2M de pacotes, consegues puxar bibliotecas para quase tudo (HTTP, autenticação, testes). O `npm` vem instalado com o Node.

### Mini linha temporal

| Ano       | Evento                                                                                         |
| --------- | ---------------------------------------------------------------------------------------------- |
| 2008      | Google lança o motor V8 (rápido, JIT).                                                         |
| 2009      | Ryan Dahl combina V8 + libuv e cria Node.js.                                                   |
| 2010-2014 | Explosão de módulos npm, Express surge como micro-framework.                                   |
| 2015      | Fundação Node.js é criada; LTS passa a ser o standard.                                         |
| Hoje      | Node é usado por gigantes (Netflix, PayPal, NASA) e por escolas para ensinar back-end moderno. |

---

## 2) Porque precisamos de Node?

-   **Mesmo idioma no front e no back.** A equipa aprende um só idioma e consegue partilhar utilitários (validações, modelos de dados).
-   **Tempo de resposta baixo em APIs.** Graças ao event loop, um servidor Express aguenta milhares de pedidos I/O-bound (fazer fetch a APIs, bases de dados) sem bloquear.
-   **Ferramentas de build.** Webpack, Vite, ESLint, Prettier e quase todo o tooling web é escrito em Node. Mesmo que construas o back noutra linguagem, vais usar Node para tooling.
-   **Comunidade gigante.** Problema noutra tecnologia? Provavelmente existe um pacote npm que resolve.

---

## 3) Como o Node funciona por dentro?

1. **V8** compila o teu JavaScript para código máquina em tempo real (JIT).
2. **Libuv** gere threads para operações de rede, ficheiros e timers.
3. **Event loop** observa filas de tarefas (timers, I/O, microtasks) e decide o que executar a seguir.
4. **Bindings nativos**: Node expõe módulos como `fs`, `http`, `crypto`, escritos em C/C++.

![event loop summary](https://upload.wikimedia.org/wikipedia/commons/thumb/d/d9/Node.js_event_loop_diagram.svg/640px-Node.js_event_loop_diagram.svg.png)

> Explica ao aluno que o JavaScript continua single-threaded, mas o Node usa threads auxiliares para operações demoradas e devolve o resultado ao event loop quando termina.

---

## 4) Quando usar ou evitar Node?

| Ideal quando…                                                                  | Menos indicado quando…                                                                |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- |
| APIs REST leves que fazem muitas chamadas I/O (bases de dados, APIs externas). | Necessitas de operações CPU-intensivas (renderização 3D, machine learning pesado).    |
| Aplicações em tempo real (chat, notificações, sockets).                        | Precisas de forte tipagem e ferramentas corporativas específicas (Java/Spring, .NET). |
| Ferramentas de build/CLI e automações.                                         | Tens dependências nativas complexas que já existem noutra linguagem.                  |

Quando o trabalho é muito pesado em CPU, podes usar **Worker Threads** ou escrever módulos nativos, mas avaliar se outra linguagem não seria melhor.

---

## 5) Instalar e manter Node

-   **Versão recomendada:** LTS (Long Term Support). Hoje é Node 20 LTS ou superior. Evita versões “Current” em produção.
-   **Gestores de versão:** `nvm`, `fnm` ou `asdf` permitem trocar de versão rapidamente. Ideal quando o aluno usa portátil partilhado.
-   **Atualizações:** corre `node -v` e `npm -v` para confirmar. Atualiza com `nvm install --lts` ou descarrega do site oficial.
-   **Verificação:** `node --version`, `npm --version`, `npx envinfo --binaries`.

---

## 6) Primeiro script

```bash
node -e "console.log('Olá Node!')"
```

Ou cria `hello.js`:

```js
console.log("Primeiro script Node");
```

e corre `node hello.js`. Mostra aos alunos que o terminal agora executa JavaScript nativamente.

---

## 7) Glossário rápido

-   **Runtime:** ambiente que entende e executa JavaScript (Node, Deno, Bun, browser).
-   **Event loop:** orquestrador que decide qual função corre a seguir.
-   **LTS:** versão com suporte longo (18 meses) — a mais estável.
-   **npm:** Node Package Manager, instala dependências (bibliotecas).
-   **npx:** executa comandos de pacotes sem instalá-los globalmente.
-   **ES Modules:** sintaxe moderna de import/export.
-   **CommonJS:** sistema antigo baseado em `require`/`module.exports`.

---

## 8) Próximos passos

-   Lê o capítulo `00_setup_projeto.md` para configurar a estrutura base.
-   Se o foco for Express, segue depois para `03_http_vs_express.md` e `04_express_basico.md`.
-   Para entender módulos, continua com `01_modulos_node.md`.

---

## 9) Arquitetura cliente-servidor aplicada ao Node

-   **Cliente**: qualquer aplicação que consome a API (browser, app móvel, outra API). Normalmente envia pedidos HTTP via `fetch`, Axios ou `XMLHttpRequest`.
-   **Servidor Node**: aplicação Express (ou HTTP nativo) que escuta numa porta (`http://localhost:3000`) e responde a pedidos.
-   **Canal**: protocolo HTTP/HTTPS transporta o pedido e a resposta em formato texto (headers + body).

Fluxo típico:

1. O cliente envia `GET https://api.exemplo.com/api/v1/todos`.
2. O Node recebe o pedido, passa pelos middlewares (autenticação, logs…).
3. O controller chama serviços e repositories.
4. O servidor devolve uma resposta com `status` e `body` JSON.

### Componentes-chave

-   **DNS / URL**: traduz `api.exemplo.com` para IP (ex.: 185.199.108.153).
-   **Porta**: número que identifica o serviço (80/443 público, 3000/5173 em dev).
-   **Stateless**: cada pedido deve conter tudo o que é necessário (token, filtros). Node trata cada request como novo, facilitando escalabilidade horizontal (vários servidores).

### Demonstração visual (explica ao aluno)

```
Browser (cliente) --HTTP--> Express (servidor) --fs/DB--> Ficheiro/BD
                               |                        ^
                               \------ resposta JSON ----/
```

---

## 10) O que é uma API REST?

-   **API** (Application Programming Interface): contrato que define como duas aplicações comunicam.
-   **REST** (Representational State Transfer): conjunto de princípios para APIs HTTP previsíveis:
    1. **Recursos** representados por URLs (ex.: `/api/v1/todos`).
    2. **Métodos HTTP** representam ações: `GET` (ler), `POST` (criar), `PATCH/PUT` (atualizar), `DELETE` (remover).
    3. **Stateless**: cada pedido independente, sem guardar estado no servidor entre chamadas.
    4. **Representações múltiplas**: mesma informação pode ser JSON, XML, etc. (nós usamos JSON).

### Exemplo REST com Node/Express

| Método | URL                 | Descrição                         |
| ------ | ------------------- | --------------------------------- |
| GET    | `/api/v1/todos`     | Lista todas as tarefas.           |
| POST   | `/api/v1/todos`     | Cria nova tarefa (body JSON).     |
| GET    | `/api/v1/todos/:id` | Lê uma tarefa específica.         |
| PATCH  | `/api/v1/todos/:id` | Atualiza parcialmente um recurso. |
| DELETE | `/api/v1/todos/:id` | Remove uma tarefa.                |

### Boas práticas a reforçar

-   Usa códigos HTTP adequados (200 sucesso, 201 criado, 400 erro do cliente, 500 erro do servidor).
-   Documenta o formato do JSON de entrada/saída (pode ser num README ou com Swagger).
-   Hiperlinks (HATEOAS) são opcionais neste nível; concentra-te em endpoints claros e consistentes.

### Relação com Node

-   Express simplifica a criação de rotas REST com `app.get/post/patch/delete`.
-   Middlewares tratam autenticação, parsing de body e CORS — componentes críticos em APIs REST.
-   Por ser leve e rápido em I/O, Node é ideal para gateways REST que agregam dados de várias fontes.

---

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Adicionadas secções sobre arquitetura cliente-servidor aplicada ao Node e princípios de APIs REST.
-   **v1.0.0 — 2025-11-10**
    -   Criação do capítulo introdutório com história, arquitetura, casos de uso e glossário do Node.js.
