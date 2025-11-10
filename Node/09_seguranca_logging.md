# 09) Segurança, logging e compressão

## CORS
Controla que origens podem chamar a API.
- Se credentials: true, o origin não pode ser "*". Define um domínio específico.
- Lado do browser usa withCredentials: true.

## Helmet
Headers de segurança (CSP, X-Frame-Options e outros).

## Rate-limit
Protege contra abuso.

## Logging
- Em desenvolvimento: morgan.
- Em produção: pino (estruturado) é boa opção.

### Instalar (opcionais)
```bash
npm i express-rate-limit pino pino-http pino-pretty
```

### Exemplo mínimo
Vê 04_express_basico.md para a integração.

## Nota rápida sobre autenticação (futuro)
- Nunca guardes passwords em claro. Usa argon2 ou bcryptjs.
- Sessões JWT com expiração curta e refresh tokens. Idealmente em cookies HTTP-Only.

## Porque estas proteções interessam para o 12.º ano?

-   **CORS** mostra como o browser protege o utilizador: por defeito, uma página não pode pedir dados a outro domínio. Ao configurar `cors`, explicas as noções de origem, métodos e credenciais.
-   **Helmet** resume anos de boas práticas de segurança num único middleware. Cada header previne um tipo diferente de ataque (Clickjacking, XSS, sniffing de MIME).
-   **Rate-limit** ensina sobre disponibilidade. Mesmo que a API esteja no Render gratuito, limitar 100 pedidos / 15 min impede abuso.
-   **Logging** é a “caixa negra” do servidor. `morgan` escreve linhas legíveis, `pino` gera JSON estruturado que podes enviar para ferramentas de observabilidade.
-   **Compression** mostra a importância de performance: menos bytes enviados → respostas mais rápidas, especialmente em ligações móveis.

## Exemplo completo (copiar para `src/app.js`)

```js
import helmet from "helmet";
import cors from "cors";
import compression from "compression";
import morgan from "morgan";
import rateLimit from "express-rate-limit";

app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN?.split(",") ?? "*", credentials: true }));
app.use(compression());
app.use(morgan(process.env.NODE_ENV === "production" ? "combined" : "dev"));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 200 }));
```

Explica aos alunos como transformar `CORS_ORIGIN` numa lista separada por vírgulas, permitindo só os domínios necessários.

## Logging estruturado com Pino

```js
import pino from "pino";
import pinoHttp from "pino-http";
const logger = pino({ level: process.env.LOG_LEVEL || "info" });
app.use(pinoHttp({ logger }));
```

-   Agora cada linha contém JSON com `req.method`, `req.url`, `res.statusCode` e tempo de resposta.
-   Em aulas podes mostrar como filtrar apenas erros (`LOG_LEVEL=error npm run dev`).

## Autenticação — visão mais detalhada

1. Guardar passwords com `bcryptjs`:
   ```js
   import bcrypt from "bcryptjs";
   const hash = await bcrypt.hash(password, 12);
   const ok = await bcrypt.compare(passwordTentada, hashGuardado);
   ```
2. Criar tokens JWT:
   ```js
   import jwt from "jsonwebtoken";
   const token = jwt.sign({ sub: user.id }, process.env.JWT_SECRET, { expiresIn: "15m" });
   ```
3. Enviar num cookie HTTP-Only ou no header `Authorization: Bearer`.

Mesmo que ainda não implementem, contextualiza porque estas práticas são indispensáveis fora da sala de aula.

## Changelog

-   **v1.1.0 — 2025-11-10**
    -   Acrescentadas descrições detalhadas de CORS, Helmet, rate-limit, logging, compressão e autenticação.
    -   Incluído snippet completo de configuração e secção de changelog.
