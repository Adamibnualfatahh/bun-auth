import Elysia from "elysia";
import { auth } from "~modules/auth";
import { cookie } from "@elysiajs/cookie";
import { jwt } from "@elysiajs/jwt";
import {env} from "bun";
const app = new Elysia()
    .group("/api", (app) =>
        app
            .use(
                jwt({
                    name: "jwt",
                    secret: Bun.env.JWT_SECRET!,
                })
            )
            .use(cookie())
            .use(auth)
    )
    .listen(env.PORT! || 3000);
console.log(
    `🦊 Server is running at ${app.server?.hostname}:${app.server?.port}`
);