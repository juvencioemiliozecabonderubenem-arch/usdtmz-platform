import { neon } from "@neondatabase/serverless";
import { createHash } from "node:crypto";

/* =========================================================
   DATABASE
   ========================================================= */

function getDatabaseUrl() {
  return (
    process.env.URL_DO_BANCO_DE_DADOS ||
    process.env.POSTGRES_URL ||
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL_NON_POOLING ||
    process.env.DATABASE_URL_UNPOOLED
  );
}

/* =========================================================
   HELPERS
   ========================================================= */

function normalizeText(value) {
  return String(value || "").trim();
}

function normalizePhone(value) {
  return normalizeText(value)
    .replace(/\s+/g, "")
    .replace(/-/g, "");
}

function normalizeEmail(value) {
  return normalizeText(value).toLowerCase();
}

function hashPassword(password) {
  return createHash("sha256")
    .update(password)
    .digest("hex");
}

function isValidPhone(phone) {
  /*
   * Aceita números moçambicanos
   * com ou sem +258.
   */
  const cleaned = normalizePhone(phone);

  return (
    /^(?:\+258|258)?8[2-7]\d{7}$/.test(
      cleaned
    )
  );
}

function isValidEmail(email) {
  if (!email) {
    return true;
  }

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}

/* =========================================================
   HANDLER
   ========================================================= */

export default async function handler(
  req,
  res
) {
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message:
        "Método não permitido."
    });
  }

  const databaseUrl =
    getDatabaseUrl();

  if (!databaseUrl) {
    return res.status(500).json({
      success: false,
      message:
        "Banco de dados não configurado."
    });
  }

  const body =
    req.body || {};

  const name =
    normalizeText(
      body.name
    );

  const phone =
    normalizePhone(
      body.phone
    );

  const email =
    normalizeEmail(
      body.email
    );

  const password =
    normalizeText(
      body.password
    );

  /* =======================================================
     VALIDAÇÃO
     ======================================================= */

  if (!name) {
    return res.status(400).json({
      success: false,
      message:
        "Nome é obrigatório."
    });
  }

  if (name.length < 2) {
    return res.status(400).json({
      success: false,
      message:
        "O nome deve ter pelo menos 2 caracteres."
    });
  }

  if (!phone) {
    return res.status(400).json({
      success: false,
      message:
        "Telefone é obrigatório."
    });
  }

  if (!isValidPhone(phone)) {
    return res.status(400).json({
      success: false,
      message:
        "Número de telefone moçambicano inválido."
    });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({
      success: false,
      message:
        "E-mail inválido."
    });
  }

  if (!password) {
    return res.status(400).json({
      success: false,
      message:
        "Palavra-passe é obrigatória."
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      success: false,
      message:
        "A palavra-passe deve ter pelo menos 6 caracteres."
    });
  }

  try {
    const sql =
      neon(databaseUrl);

    /* =====================================================
       VERIFICAR TELEFONE
       ===================================================== */

    const phoneExists =
      await sql`
        SELECT
          id
        FROM users
        WHERE phone =
          ${phone}
        LIMIT 1
      `;

    if (phoneExists.length) {
      return res.status(409).json({
        success: false,
        message:
          "Este número de telefone já está registado."
      });
    }

    /* =====================================================
       VERIFICAR E-MAIL
       ===================================================== */

    if (email) {
      const emailExists =
        await sql`
          SELECT
            id
          FROM users
          WHERE LOWER(email) =
            ${email}
          LIMIT 1
        `;

      if (emailExists.length) {
        return res.status(409).json({
          success: false,
          message:
            "Este e-mail já está registado."
        });
      }
    }

    /* =====================================================
       PASSWORD
       ===================================================== */

    const passwordHash =
      hashPassword(
        password
      );

    /* =====================================================
       CRIAR UTILIZADOR
       ===================================================== */

    const created =
      await sql`
        INSERT INTO users (
          name,
          phone,
          email,
          password
        )
        VALUES (
          ${name},
          ${phone},
          ${email || null},
          ${passwordHash}
        )
        RETURNING
          id,
          name,
          phone,
          email,
          created_at
      `;

    if (!created.length) {
      return res.status(500).json({
        success: false,
        message:
          "Não foi possível criar o utilizador."
      });
    }

    const user =
      created[0];

    /*
     * Nunca devolvemos password ou
     * password_hash para o frontend.
     */

    return res.status(201).json({
      success: true,
      message:
        "Utilizador registado com sucesso.",
      user
    });
  } catch (error) {
    console.error(
      "REGISTER USER ERROR:",
      error
    );

    /*
     * Trata possíveis erros de
     * constraint UNIQUE do PostgreSQL.
     */
    if (
      String(error?.message || "")
        .toLowerCase()
        .includes("unique")
    ) {
      return res.status(409).json({
        success: false,
        message:
          "Telefone ou e-mail já está registado."
      });
    }

    return res.status(500).json({
      success: false,
      message:
        "Erro interno ao registar utilizador.",
      detail:
        error?.message ||
        "Erro desconhecido."
    });
  }
}
