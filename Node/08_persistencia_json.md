# 08) Persistência em ficheiro JSON

Objetivo didático para começar. Depois trocamos por MongoDB.

```js
// src/repositories/todos.repo.file.js
import path from "node:path";
import { fileURLToPath } from "node:url";
import fs from "node:fs/promises";
import crypto from "node:crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const F = path.join(__dirname, "..", "data", "todos.json");

async function lerTodos() {
  try {
    return JSON.parse(await fs.readFile(F, "utf8"));
  } catch (e) {
    if (e.code === "ENOENT") return [];
    throw e;
  }
}

async function gravarTodos(lista) {
  await fs.mkdir(path.dirname(F), { recursive: true });
  const tmp = F + ".tmp";
  await fs.writeFile(tmp, JSON.stringify(lista, null, 2), "utf8");
  await fs.rename(tmp, F);
}

export async function listar() {
  return lerTodos();
}

export async function obter(id) {
  const L = await lerTodos();
  return L.find((t) => t.id === id) || null;
}

export async function criar({ titulo, concluido = false }) {
  const novo = { id: crypto.randomUUID(), titulo, concluido, criadoEm: Date.now() };
  const L = await lerTodos();
  L.push(novo);
  await gravarTodos(L);
  return novo;
}

export async function atualizar(id, patch) {
  const L = await lerTodos();
  const idx = L.findIndex((t) => t.id === id);
  if (idx === -1) return null;
  L[idx] = { ...L[idx], ...patch, atualizadoEm: Date.now() };
  await gravarTodos(L);
  return L[idx];
}

export async function remover(id) {
  const L = await lerTodos();
  const filtrado = L.filter((t) => t.id !== id);
  if (filtrado.length === L.length) return false;
  await gravarTodos(filtrado);
  return true;
}
```

```js
// src/services/todos.service.js
import * as repo from "../repositories/todos.repo.file.js";
export const listar = () => repo.listar();
export const obter = (id) => repo.obter(id);
export const criar = (data) => repo.criar(data);
export const atualizar = (id, patch) => repo.atualizar(id, patch);
export const remover = (id) => repo.remover(id);
```

## Porque usar ficheiros para começar?

-   Ajuda a visualizar o ciclo completo **API → ficheiro → resposta** sem instalar bases de dados.
-   O JSON é legível para alunos: podes abrir o ficheiro e ver imediatamente a lista de tarefas.
-   Serve como degrau para mais tarde trocar por MongoDB/PostgreSQL. A API e os services mantêm-se, apenas o repository é reescrito.

## Cuidados importantes

-   Usa `fs.mkdir(..., { recursive: true })` antes de escrever para garantir que a pasta existe.
-   Escreve sempre para um ficheiro temporário (`.tmp`) e depois `rename`. Isto impede que o ficheiro fique corrompido se a escrita falhar a meio.
-   Estas operações não são concorrentes: dois pedidos ao mesmo tempo podem sobrescrever dados. É aceitável na aula mas explica que uma BD resolve este problema.

## Extensões sugeridas para os alunos

1. Adicionar campo `prioridade` e filtrar `listar()` para devolver os “urgentes” primeiro.
2. Criar função `pesquisar(padrao)` no repository usando `String.prototype.includes`.
3. Guardar estatísticas (número de tarefas concluídas) num ficheiro separado.

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Incluídas explicações sobre segurança ao escrever ficheiros, limitações de concorrência e exercícios de extensão.
    -   Secção de changelog adicionada.
