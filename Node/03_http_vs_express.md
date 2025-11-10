# 03) HTTP nativo vs Express

## HTTP nativo (exemplo mínimo)

```js
import http from "node:http";

const server = http.createServer((req, res) => {
  if (req.url === "/") return res.writeHead(200).end("Olá");
  res.writeHead(404).end("Não encontrado");
});

server.listen(3000);
```

## Porque Express
- Roteamento, middlewares, express.json, gestão de erros, ecossistema grande.
- Ideal para aulas e projetos reais.

Nos ficheiros seguintes montamos a app Express passo a passo.

## Como funciona o pedido/resposta na prática?

1. O browser faz um pedido HTTP (`GET /api/health`).
2. O Node recebe o pedido através do `http.createServer`.
3. Analisas manualmente o URL, método e body.
4. Escreves o cabeçalho (`res.writeHead`) e o corpo (`res.end`).

O módulo nativo dá-te total controlo, mas tens de:
-   Converter o body manualmente (JSON, form-data, etc.).
-   Tratar erros em todos os `try/catch`.
-   Escrever lógica repetida para cada rota.

O Express automatiza estes passos:
-   `express.json()` já converte o body.
-   Middlewares permitem compor funcionalidades (CORS, autenticação...).
-   O roteador (`app.get`, `app.post`) associa funções diretamente às rotas.
-   Um único handler de erros consegue apanhar problemas em qualquer rota.

## Quando usar HTTP puro?

-   Microprojetos educativos onde queres mostrar “o que acontece nos bastidores”.
-   Serviços ultra minimalistas (por exemplo, responder sempre com um ficheiro).
-   Situações em que não queres dependências externas. Ainda assim, Express é leve (±20 kB).

## Analogias para explicar em aula

-   **HTTP nativo** é como cozinhar tudo do zero: controlas cada ingrediente mas demora mais.
-   **Express** é como uma cozinha com bancadas organizadas e utensílios prontos — consegues focar-te na receita (regras de negócio) em vez de reinventar cada passo.

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Adicionadas explicações sobre o ciclo pedido/resposta e critérios para escolher entre HTTP nativo e Express.
    -   Acrescentada secção de changelog.
