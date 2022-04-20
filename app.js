/* IMPORTS */
require('dotenv').config(); //
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Config JSON response
app.use(express.json()); //"ler" json

// Models
const User = require('./models/User');
const { json } = require('express/lib/response');

// Public Route
app.get('/', (req, res) => {
  res.status(200).json({msg: "bem vindo a nossa API"});
});

// Registe User
app.post('/auth/register', async(req, res) => {//

  const { name, email, password, conformPassword } = req.body;

  // validations
  if(!name){
    return res.status(422).json({msg: "Nome é obrigatório"})
  }

  if(!email){
    return res.status(422).json({msg: "Email é obrigatório"})
  }

  if(!password){
    return res.status(422).json({msg: "Senha é obrigatório"})
  }

  if(password !== conformPassword){
    return res.status(422).json({msg: "As senhas não conferem"})
  }

  // CHECK IF USER EXISTS
  const userExists = await User.findOne({email: email}) // filtra usuarios com um objeto, vendo se tem o campo email igual o que esta sendo criado //pq esta em await?

  if(userExists){
    return res.status(422).json({msg: "Esse email já está cadastrado"})
  }

  // create password
  const salt = await bcrypt.genSalt(12) //
  const passwordHash = await bcrypt.hash(password, salt) //

  // create user

  const user = new User({
    name,
    email,
    password: passwordHash
  })

  try{

    await user.save() //

    res.status(201).json({msg: 'Usuário criado com sucesso'})

  }catch(error){
    console.log(error)
    res.status(500).json({msg: 'Aconteceu um erro no servidor, tente novamente mais tarde'})
  }
});

// Login User
app.post("/auth/login", async (req, res) => { //funcoes assincrona para esperar resposta do banco -entender async await-

  const [ email, password ] = req.body;

  //validation
  if(!email){
    return res.status(422).json({msg: "Email é obrigatório"})
  }

  if(!password){
    return res.status(422).json({msg: "Senha é obrigatório"})
  }

  //check if user exist
  const user = await User.findOne({email: email}) // filtra usuarios com um objeto, vendo se tem o campo email igual o que esta sendo criado //pq esta em await?

  if(!user){
    return res.status(404).json({msg: "Usuário não encontrado"})
  }

  //check if password match
  const checkPassword = await bcrypt.compare(password, user.password)

  if(!checkPassword){
    return res.status(422).json({msg: "Senha inválida"})
  }

  try{
    const secret = process.env.SECRET;

    const token = jwt.sign({
      id: user._id
    },
    secret
    )

    res.status(200).json({msg: "Autenticação realizada com sucesso", token})

  }catch(error){
    console.log(error)
    res.status(500).json({msg: 'Aconteceu um erro no servidor, tente novamente mais tarde'})
  }
  
})

// Private route
// parametro "next" - deu tudo certo continua a requisição, ou deu errado e saio fora
// middleware para transformar em rota privada
function checkToken(req, res, next){

  const authHeader = req.headers['authorizations'];
  const token = authHeader && authHeader.split(" ")[1];

  if(!token){
    return res.status(401).json({msg: "Acesso negado"})
  }

  try{

    const secret = process.env.SECRET;

    jwt.verify(token, secret);

    next()
  }catch(error){
    console.log(error)
    res.status(400).json({msg: "Token inválido"})
  }

}

app.get('/user/:id', checkToken, async (req, res) => { // esse middleware é usado no segundo parametro indicando estar em uma rota especifica, diferente do express.json que usamos em todas as rotas

  const id = req.params.id;

  const user = await User.findById(id, '-password')

  if(!user){
    return res.status(404).json({msg: "Usuário não encontrado"})
  }

  res.status(200).json({ user })
})





//BANCO DE DADOS
//Credencials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.3l7dx.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`)
.then(()=>{
  app.listen(3000);
  console.log("Conectou ao banco!")
})
.catch((err) => console.log(err))
