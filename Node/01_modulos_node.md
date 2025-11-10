# 01) Módulos: ES Modules vs CommonJS

-   ESM (moderno): import ... from '...' e export.
-   CommonJS (antigo): require() e module.exports.

Neste curso usamos ESM.

-   Garante "type": "module" no package.json.
-   Nos imports relativos escreve sempre a extensão: ./ficheiro.js.

## Exemplos

```js
// utils/math.js
export const soma = (a, b) => a + b;

// noutro ficheiro
import { soma } from "./utils/math.js";
```

## Import dinâmico

```js
const mod = await import("./utils/math.js");
console.log(mod.soma(2, 3));
```

## \_\_dirname em ESM

Em ES Modules não existe \_\_dirname. Usa:

```js
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
```

## JSON

Prefere fs/promises com JSON.parse e JSON.stringify.
(Node 20+ permite import de JSON com assert, fora do âmbito aqui).

## Porque existem dois sistemas de módulos?

-   **CommonJS** nasceu com o Node em 2009. Era a solução exclusiva do runtime e funcionava com `require`. O código é carregado de forma síncrona e não pode usar `await` na raiz.
-   **ES Modules (ESM)** fazem parte da linguagem JavaScript “oficial”. Chegaram ao Node mais tarde, mas alinham o servidor com o browser, permitindo partilhar código e usar `import/export` em todo o lado.
-   Ao definir `"type": "module"` no `package.json`, estás a dizer ao Node para interpretar todos os ficheiros `.js` como ESM. Caso contrário, ele assume CommonJS e vais ter erros como `Cannot use import statement outside a module`.

## Tipos de export

1. **Named exports** (recomendado)

```js
export function geraToken() {}
export const MAX_USERS = 10;
```

No import, usas `{ geraToken }`. Se tentares importar algo que não existe, recebes um erro claro.

2. **Default exports**

```js
export default function soma(a, b) {
  return a + b;
}
```

Só pode haver um `default` por ficheiro e, ao importar, podes dar o nome que quiseres (`import somar from "./math.js";`). Evita default quando tens vários utilitários porque fica menos explícito.

## Top-level await e import dinâmico

-   Em ESM podes usar `await` fora de funções async. Isto é útil para carregar ficheiros de configuração antes de arrancar o servidor.
-   O `import()` dinâmico devolve uma `Promise` e permite carregar módulos apenas quando precisas (por exemplo, só carregar `node:fs` dentro de uma função CLI).

```js
// Carregar apenas quando o comando admin é usado
async function carregarAdmin() {
  const mod = await import("./admin-tools.js");
  return mod;
}
```

## Boas práticas para 12.º ano

-   **Imports relativos com extensão** (`./utils/math.js`) evitam ambiguidades no Node e tornam o caminho explícito para o aluno.
-   **Agrupa exports relacionados**: em vez de criar mil ficheiros, podes exportar vários helpers a partir de `utils/index.js`, mas lembra-te de manter a leitura fácil.
-   **Usa `index.js` apenas quando fizer sentido**: se precisares de expor vários routers (`export * from "./todos.router.js"`), explica sempre de onde vem cada função.

## Checklist mental quando o import falha

1. O `package.json` tem `"type": "module"`?
2. Estás a usar caminhos relativos correctos (`../` volta uma pasta atrás)?
3. Copiaste a extensão `.js`?
4. O ficheiro exporta realmente aquilo que estás a importar?
5. Reiniciaste o Node depois de alterar `package.json`?

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Acrescentadas explicações sobre a diferença histórica entre CommonJS e ES Modules, tipos de export e top-level await.
    -   Incluído checklist para depurar imports e secção de changelog.
