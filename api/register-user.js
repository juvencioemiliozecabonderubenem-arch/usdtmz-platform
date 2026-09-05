import { neon } from "@neondatabase/serverless";
import { scryptSync, randomBytes } from "node:crypto";

function hashPassword(password) {
  const salt = randomBytes(16).toString("hex");

  const hash = scryptSync(
    password,
    salt,
    64
  ).toString("hex");

  return `${salt}:${hash}`;
}

export default async function handler(req, res) {

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Método não permitido."
    });
  }

  const databaseUrl =
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED;

  if (!databaseUrl) {
    return res.status(500).json({
      success: false,
      message: "Banco de dados não configurado."
    });
  }

  const {
    name,
    email,
    phone,
    password
  } = req.body || {};

  if (!name || !email || !password) {
    return res.status(400).json({
      success: false,
      message: "Nome, email e senha são obrigatórios."
    });
  }

  if (password.length < 8) {
    return res.status(400).json({
      success: false,
      message: "A senha deve ter pelo menos 8 caracteres."
    });
  }

  try {

    const sql = neon(databaseUrl);

    const normalizedEmail =
      email.trim().toLowerCase();

    const existingUser = await sql`
      SELECT id
      FROM users
      WHERE email = ${normalizedEmail}
      LIMIT 1
    `;

    if (existingUser.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Este email já está cadastrado."
      });
    }

    const passwordHash =
      hashPassword(password);

    const result = await sql`
      INSERT INTO users (
        name,
        email,
        phone,
        password_hash,
        status
      )
      VALUES (
        ${name.trim()},
        ${normalizedEmail},
        ${phone ? phone.trim() : null},
        ${passwordHash},
        'ACTIVE'
      )
      RETURNING
        id,
        name,
        email,
        phone,
        status,
        created_at
    `;

    const user = result[0];

    await sql`
      INSERT INTO wallets (
        user_id,
        usdt_balance
      )
      VALUES (
        ${user.id},
        0
      )
      ON CONFLICT (user_id)
      DO NOTHING
    `;

    return res.status(201).json({
      success: true,
      message: "Utilizador criado com sucesso.",
      user
    });

  } catch (error) {

    console.error(
      "Erro ao criar utilizador:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Erro ao criar utilizador."
    });
  }
}
