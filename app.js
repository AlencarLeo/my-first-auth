/* IMPORTS */
require('dotenv').config(); //
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();

// Config JSON response
app.use(express.json());

// Models
const User = require('./models/User');

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
    password
  })

  try{

    await user.save() //

    res.status(201).json({msg: 'Usuário criado com sucesso'})

  }catch(error){
    console.log(error)
    res.status(500).json({msg: 'Aconteceu um erro no servidor, tente novamente mais tarde'})
  }
});

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
