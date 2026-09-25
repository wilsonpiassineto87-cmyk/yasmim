# API do Bússola Naval (Cloudflare Worker + D1)

Este Worker guarda os usuários e o progresso do app num banco de dados
de verdade (Cloudflare D1), em vez de só no navegador.

O banco `yasmim-usuarios` já foi criado, com as tabelas `users` e
`user_progress`. Falta publicar este Worker, o que precisa ser feito
pelo terminal (é a única etapa que exige login interativo no
Cloudflare, algo que não dá pra fazer por aqui).

## Passo a passo

1. Instale o Node.js (se ainda não tiver): https://nodejs.org

2. Abra um terminal nesta pasta (`worker/`) e faça login no Cloudflare:
   ```
   npx wrangler login
   ```
   Isso abre o navegador para você autorizar.

3. Defina o segredo usado para assinar os tokens de login (escolha uma
   frase aleatória só sua, e guarde-a):
   ```
   npx wrangler secret put TOKEN_SECRET
   ```

4. Publique o Worker:
   ```
   npx wrangler deploy
   ```
   Ao final, o terminal mostra a URL pública, algo como:
   ```
   https://yasmim-api.SEU-SUBDOMINIO.workers.dev
   ```

5. Copie essa URL e cole no arquivo principal do site
   (`../Qwen_html_20260923_j49x2yg4s.html`), na linha:
   ```js
   var API_BASE = '';
   ```
   trocando para:
   ```js
   var API_BASE = 'https://yasmim-api.SEU-SUBDOMINIO.workers.dev';
   ```

6. Suba essa mudança pro GitHub (commit + push) e pronto: o cadastro e
   o login passam a usar o banco de dados de verdade, com senha
   protegida por hash (nunca fica salva em texto puro). O app
   continua funcionando offline como fallback se a API não responder.

## O que o Worker faz

- `POST /register` — cria conta (nome, usuário, senha)
- `POST /login` — autentica e devolve um token
- `GET /progress?token=...` — busca o progresso salvo do usuário
- `POST /progress` — salva o progresso do usuário

Senhas nunca são salvas em texto puro: usamos PBKDF2 (100.000
iterações) com um salt aleatório por usuário.
