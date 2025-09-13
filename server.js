const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000; // ⚠️ Alterado para usar variável de ambiente
const SECRET = "segredo-super-seguro";

// Middleware
app.use(cors());
app.use(express.json());

// Banco de dados
const db = new sqlite3.Database(":memory:");

// Criar tabelas
db.serialize(() => {
  db.run(
    "CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, balance REAL)"
  );

  // Criar o "Banco Central"
  const senhaHash = bcrypt.hashSync("admin123", 10);
  db.run(
    "INSERT INTO users (username, password, balance) VALUES (?, ?, ?)",
    ["banco_central", senhaHash, 10000]
  );
});

// Função para autenticação
function autenticar(req, res, next) {
  const token = req.headers["authorization"];
  if (!token) return res.status(403).json({ error: "Token não fornecido" });

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = user;
    next();
  });
}

// Registrar usuário
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const hash = bcrypt.hashSync(password, 10);
  db.run(
    "INSERT INTO users (username, password, balance) VALUES (?, ?, ?)",
    [username, hash, 100],
    function (err) {
      if (err) return res.status(400).json({ error: "Usuário já existe" });
      res.json({ message: "Usuário registrado com sucesso" });
    }
  );
});

// Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], (err, row) => {
    if (!row) return res.status(400).json({ error: "Usuário não encontrado" });

    if (!bcrypt.compareSync(password, row.password)) {
      return res.status(400).json({ error: "Senha incorreta" });
    }

    const token = jwt.sign({ id: row.id, username: row.username }, SECRET, {
      expiresIn: "1h",
    });
    res.json({ token });
  });
});

// Ver saldo
app.get("/saldo", autenticar, (req, res) => {
  db.get("SELECT balance FROM users WHERE id = ?", [req.user.id], (err, row) => {
    res.json({ saldo: row.balance });
  });
});

// Transferir dinheiro
app.post("/transfer", autenticar, (req, res) => {
  const { para, valor } = req.body;

  db.serialize(() => {
    db.get("SELECT * FROM users WHERE id = ?", [req.user.id], (err, remetente) => {
      if (!remetente || remetente.balance < valor) {
        return res.status(400).json({ error: "Saldo insuficiente" });
      }

      db.get("SELECT * FROM users WHERE username = ?", [para], (err, destinatario) => {
        if (!destinatario) {
          return res.status(400).json({ error: "Destinatário não encontrado" });
        }

        db.run("UPDATE users SET balance = balance - ? WHERE id = ?", [valor, remetente.id]);
        db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [valor, destinatario.id]);

        res.json({ message: "Transferência realizada com sucesso" });
      });
    });
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});

