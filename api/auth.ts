import { VercelRequest, VercelResponse } from "@vercel/node";
import crypto from "crypto";
// import { create } from "./_lib/oauth2";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import helmet from "helmet";
import { IncomingMessage, ServerResponse, createServer } from "http";

import simpleOauthModule from "simple-oauth2";

const create = () =>
  simpleOauthModule.create({
    client: {
      id: process.env.OAUTH_CLIENT_ID,
      secret: process.env.OAUTH_CLIENT_SECRET
    },
    auth: {
      tokenHost: `https://github.com`,
      tokenPath: `/login/oauth/access_token`,
      authorizePath: `/login/oauth/authorize`
    }
  });

type RenderBody = {
  (status: "success", content: { token: string; provider: "github" }): string;
  (status: "error", content: Object): string;
};
const renderBody: RenderBody = (status, content) => `
<script>
  const receiveMessage = (message) => {
    window.opener.postMessage(
      'authorization:github:${status}:${JSON.stringify(content)}',
      message.origin
    );

    window.removeEventListener("message", receiveMessage, false);
  }
  window.addEventListener("message", receiveMessage, false);
  
  window.opener.postMessage("authorizing:github", "*");
</script>
`;




dotenv.config();

const app: express.Application = express();

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        ...helmet.contentSecurityPolicy.getDefaultDirectives(),
        "script-src": ["'self'", "'unsafe-inline'"],
      },
    },
  })
);


app.use(cors({
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'X-Access-Token',
  ],
  credentials: true,
  methods: 'GET,HEAD,OPTIONS,PUT,PATCH,POST,DELETE',
  preflightContinue: false,
  origin: '*',
}));

export const randomString = () => crypto.randomBytes(4).toString(`hex`);

app.get('/api/auth', (req: express.Request, res: express.Response) => {
  const { host } = req.headers;

  const oauth2 = create();

  const url = oauth2.authorizationCode.authorizeURL({
    redirect_uri: `https://${host}/api/callback`,
    scope: `repo,user`,
    state: randomString()
  });

  res.writeHead(301, { Location: url });
  res.end();
});

const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  app(req as any, res as any);
});

export default (req: VercelRequest, res: VercelResponse) => {
  server.emit("request", req, res);
};
