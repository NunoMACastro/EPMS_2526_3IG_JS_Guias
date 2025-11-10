# 02) Node core útil

## path
Construir caminhos de forma portátil.

```js
import path from "node:path";
const raiz = process.cwd();
const ficheiro = path.join(raiz, "data", "todos.json");
```

## fs/promises
I/O assíncrono.

```js
import fs from "node:fs/promises";

export async function lerJSON(caminho, fallback = null) {
  try {
    return JSON.parse(await fs.readFile(caminho, "utf8"));
  } catch (e) {
    if (e.code === "ENOENT") return fallback;
    throw e;
  }
}

export async function escreverJSON(caminho, dados) {
  await fs.mkdir(path.dirname(caminho), { recursive: true });
  const tmp = caminho + ".tmp";
  await fs.writeFile(tmp, JSON.stringify(dados, null, 2), "utf8");
  await fs.rename(tmp, caminho);
}
```

## process e os

```js
import os from "node:os";
console.log(process.env.NODE_ENV);
console.log(os.cpus().length, os.totalmem());
```

## events

```js
import { EventEmitter } from "node:events";
const bus = new EventEmitter();
bus.on("novo_todo", (todo) => console.log("Evento:", todo));
```

## crypto (IDs e hash)

```js
import crypto from "node:crypto";
const id = crypto.randomUUID();
```

## Streams
Para ficheiros grandes. Ver ideias em 13_troubleshooting.md.

## Quando usar cada módulo?

-   **`path`**: sempre que precisares de montar caminhos de ficheiros. Evita concatenar strings com `/` porque em Windows o separador é `\`. O `path.join` trata dessas diferenças automaticamente.
-   **`fs/promises`**: permite ler/escrever ficheiros de forma assíncrona usando `await`. Isto impede que o servidor bloqueie enquanto espera pelo disco.
-   **`process`**: informações sobre o processo atual (PID, env vars) e eventos como `process.on("uncaughtException", ...)`.
-   **`os`**: obtém detalhes da máquina (número de CPUs, memória). Serve para decidir quantos workers criar ou apenas para debugging.
-   **`events`**: `EventEmitter` implementa o padrão publish/subscribe. Se precisares que várias partes da aplicação reajam a algo (ex.: novo registo) podes emitir eventos em vez de chamar funções diretamente.
-   **`crypto`**: gera IDs, hashes e tokens seguros. Nunca uses `Math.random()` para algo que precise de segurança.
-   **`stream`**: ler ficheiros gigantes “aos pedaços” sem encher a RAM. Ideal para logs ou exportações CSV.

## Timers nativos

```js
setTimeout(() => console.log("Executa 1 vez"), 1000);
const id = setInterval(() => console.log("Loop"), 1000);
clearInterval(id);
```

-   O Node usa um *event loop*. Chamadas a `setTimeout` não são precisas ao milissegundo — servem apenas para dizer “executa depois”.
-   Para atrasar lógica nos serviços (ex.: enviar email 5 segundos depois), combina timers com Promises (`await new Promise((r) => setTimeout(r, 5000));`).

## Lidar com ficheiros JSON passo a passo

1. **Ler o ficheiro** com `fs.readFile`.
2. **Transformar a string em objeto** com `JSON.parse`.
3. **Editar o objeto** (push, filter, etc.).
4. **Guardar outra vez** com `JSON.stringify` e `fs.writeFile`.

Nunca alteres o ficheiro diretamente com `fs.appendFile` para JSON, porque podes corromper a estrutura.

## Dica sobre erros

-   Quase todos os métodos de `fs/promises` lançam erros com a propriedade `code`. Usa-a para reagir a casos esperados (como `ENOENT` para “ficheiro não existe”) e relança no resto.

```js
try {
  await fs.unlink("dados.txt");
} catch (e) {
  if (e.code !== "ENOENT") throw e;
}
```

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Expandidas as descrições dos módulos core e adicionado guia de timers, JSON e tratamento de erros.
    -   Criada esta secção de changelog.
