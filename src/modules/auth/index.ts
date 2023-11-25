import { Elysia, t } from "elysia";
import { prisma } from "../../libs/prisma.ts";
import { comparePassword, hashPassword, md5hash } from "~utils/bcrypt";
import { isAuthenticated } from "~middlewares/auth";
export const auth = (app: Elysia) =>
    app.group("/auth", (app) =>
        app
            .post(
                "/signup",
                async ({ body, set }) => {
                    const { email, name, password, username } = body;
                    const emailExists = await prisma.user.findUnique({
                        where: {
                            email,
                        },
                        select: {
                            id: true,
                        },
                    });
                    if (emailExists) {
                        set.status = 400;
                        return {
                            success: false,
                            data: null,
                            message: "Email address already in use.",
                        };
                    }

                    const usernameExists = await prisma.user.findUnique({
                        where: {
                            username,
                        },
                        select: {
                            id: true,
                        },
                    });

                    if (usernameExists) {
                        set.status = 400;
                        return {
                            success: false,
                            data: null,
                            message: "Someone already taken this username.",
                        };
                    }

                    const { hash, salt } = await hashPassword(password);
                    const emailHash = md5hash(email);
                    const profileImage = `https://www.gravatar.com/avatar/${emailHash}?d=identicon`;

                    const newUser = await prisma.user.create({
                        data: {
                            name,
                            email,
                            hash,
                            salt,
                            username,
                            profileImage,
                        },
                    });

                    return {
                        success: true,
                        message: "Account created",
                        data: {
                            user: newUser,
                        },
                    };
                },
                {
                    body: t.Object({
                        name: t.String(),
                        email: t.String(),
                        username: t.String(),
                        password: t.String(),
                    }),
                }
            )
            .post(
                "/login",
                async ({ body, set, jwt, setCookie }) => {
                    const { username, password } = body;
                    const user = await prisma.user.findFirst({
                        where: {
                            OR: [
                                {
                                    email: username,
                                },
                                {
                                    username,
                                },
                            ],
                        },
                        select: {
                            id: true,
                            hash: true,
                            salt: true,
                        },
                    });

                    if (!user) {
                        set.status = 400;
                        return {
                            success: false,
                            data: null,
                            message: "Invalid credentials",
                        };
                    }

                    const match = await comparePassword(password, user.salt, user.hash);
                    if (!match) {
                        set.status = 400;
                        return {
                            success: false,
                            data: null,
                            message: "Invalid credentials",
                        };
                    }

                    const accessToken = await jwt.sign({
                        userId: user.id,
                    });

                    setCookie("access_token", accessToken, {
                        maxAge: 15 * 60, // 15 minutes
                        path: "/",
                    });


                    return {
                        success: true,
                        data: null,
                        message: "Account login successfully",
                    };
                },
                {
                    body: t.Object({
                        username: t.String(),
                        password: t.String(),
                    }),
                }
            )
            .use(isAuthenticated)
            .get("/me", ({ user }) => {
                return {
                    success: true,
                    message: "Fetch authenticated user details",
                    data: {
                        user,
                    },
                };
            })
    );

