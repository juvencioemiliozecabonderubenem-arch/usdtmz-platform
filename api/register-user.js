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

    const normalizedPhone =
      phone ? phone.trim() : null;


    const existingEmail = await sql`
      SELECT id
      FROM users
      WHERE email = ${normalizedEmail}
      LIMIT 1
    `;

    if (existingEmail.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Este email já está cadastrado."
      });
    }


    if (normalizedPhone) {

      const existingPhone = await sql`
        SELECT id
        FROM users
        WHERE phone = ${normalizedPhone}
        LIMIT 1
      `;

      if (existingPhone.length > 0) {
        return res.status(409).json({
          success: false,
          message: "Este telefone já está cadastrado."
        });
      }
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
        ${normalizedPhone},
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
        wallet_address,
        network,
        asset,
        balance,
        status
      )
      VALUES (
        ${user.id},
        NULL,
        'TRON',
        'USDT',
        0,
        'ACTIVE'
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
