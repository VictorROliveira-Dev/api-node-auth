// imports
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
// configurando uso do json no express
app.use(express.json());
// importando models
const User = require("./models/User");
// public route
app.get("/", (req, res) => {
  res.status(200).json({ message: "bem vindo!" });
});
// private route
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;
  // checando se o usuário existe
  // excluindo a senha do usuário no retorno
  const user = await User.findById(id, "-password");
  if (!user) {
    return res.status(404).json({ message: "Usuario não encontrado!" });
  }
  return res.status(200).json({ user: user });
});
// função para checar o token
function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  // dividindo o token entre o "Bearer" e o token e pegando apenas o token "[1]"
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Acesso negado!" });
  }
  // validando o token
  try {
    const secret = process.env.SECRET;
    jwt.verify(token, secret);
    next();
  } catch (err) {
    return res.status(400).json({ message: "Token inválido!" });
  }
}
// registrar usuario
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmPassword } = req.body;
  // validações dos dados
  if (!name || !email || !password || !confirmPassword) {
    return res
      .status(422)
      .json({ message: "Todos os campos sao obrigatorios!" });
  }
  if (password !== confirmPassword) {
    return res.status(422).json({ message: "As senhas devem ser iguais!" });
  }
  // verificando se o usuario ja existe
  const userExists = await User.findOne({ email: email });
  if (userExists) {
    return res.status(422).json({ message: "Email ja cadastrado!" });
  }
  // criando a senha
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);
  // criando o usuario
  const user = new User({
    name,
    email,
    password: passwordHash,
  });
  try {
    await user.save();
    return res.status(201).json({ message: "Usuario criado com sucesso!" });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});
// login usuário
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  // validando os dados
  if (!email || !password) {
    return res
      .status(422)
      .json({ message: "Todos os campos sao obrigatorios!" });
  }
  // checando se o usuário existe
  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado!" });
  }
  // verificando a senha
  const checkPassword = await bcrypt.compare(password, user.password);
  if (!checkPassword) {
    return res.status(422).json({ message: "Senha incorreta!" });
  }
  // gerando o token
  try {
    const secret = process.env.SECRET;
    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );
    res.status(200).json({ message: "Logado com sucesso!", token: token });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});
// credenciais banco
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;
// conectando ao banco
mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.nijry.mongodb.net/?retryWrites=true&w=majority`
  )
  .then(() => {
    console.log("conectado ao banco de dados");
  })
  .catch((err) => console.log(err));

app.listen(3000);
