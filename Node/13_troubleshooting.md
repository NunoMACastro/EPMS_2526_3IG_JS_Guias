# 13) Troubleshooting - erros comuns

## 1) Error [ERR_MODULE_NOT_FOUND]: Cannot find package ' .' imported from ...
Causa provável: erro de digitação no import (um espaço mais ponto ' .') ou caminho relativo sem extensão.
Solução: verifica todos os imports.
- Usa caminhos relativos corretos com extensão, por exemplo ./utils/asyncHandler.js.
- Remove espaços acidentais.

## 2) __dirname não definido em ESM
Em ES Modules não existe __dirname.
Solução:
```js
import path from "node:path";
import { fileURLToPath } from "node:url";
const __dirname = path.dirname(fileURLToPath(import.meta.url));
```

## 3) CORS com credentials: true mas bloqueado
Se credentials: true, o origin não pode ser "*".
Solução: define origin para o domínio do front, por exemplo http://localhost:5173.

## 4) Codespaces: Error forwarding port
Garante que o servidor escuta em 0.0.0.0 e não apenas localhost.
Solução: em server.js usa app.listen(PORT, "0.0.0.0", ...).
Confirma na UI do Codespaces que a porta está Public.

## 5) nodemon não reinicia
Verifica --watch src e --ext js,mjs,cjs. Corre o nodemon a partir da raiz do projeto.

## 6) ENOENT ao ler JSON
O ficheiro ainda não existe.
Solução: o repo.file.js já devolve lista vazia se não existir. Garante que a pasta existe (fs.mkdir com recursive).

## 7) Cannot set headers after they are sent
Dupla resposta no mesmo request.
Solução: retorna imediatamente quando já respondeste e não chames next depois de enviar a resposta.

## 8) Porta ocupada
Solução: muda PORT no .env ou termina o processo que ocupa a porta.

## 9) TypeError: Cannot read properties of undefined (reading '...')
Body não foi parseado.
Solução: confirma app.use(express.json()) e Content-Type: application/json no cliente.

## 10) Dicas gerais
Usa curl ou HTTPie ou Thunder Client para testar endpoints.
Mantém logs limpos e mensagens de erro claras.

## Estratégia de depuração em 5 passos

1. **Ler o erro completo**: copia a mensagem inteira, incluindo stack trace. Muitas vezes o ficheiro/linha está ali.
2. **Reproduzir de forma consistente**: cria um pedido mínimo (curl ou Thunder Client) que dispare o bug.
3. **Isolar a camada**: o problema está na rota, controller, service ou repository? Usa `console.log` estratégicos para confirmar.
4. **Escrever um teste**: se possível, cria um teste Vitest/Supertest que falha. Assim evitas regressões.
5. **Documentar a lição**: adiciona notas neste ficheiro ou no README para evitar repetir o erro.

## Ferramentas úteis

-   `npm doctor`: verifica se o Node/npm estão saudáveis.
-   `npx envinfo --system --binaries`: imprime versões úteis quando pedes ajuda.
-   `node --watch src/server.js`: alternativa moderna ao nodemon (Node 18+).

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Acrescentado método estruturado de troubleshooting e lista de ferramentas auxiliares.
    -   Criada secção de changelog.
