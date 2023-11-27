const crypto = require("crypto")
const md5 = require("md5")

const express = require("express")
const bodyParser = require("body-parser")
const hbs = require('express-handlebars');
 
const app = express()

const users = {
  admin: {
    username: "admin",
    password: "79535974a14bcb27ae14bb398972c320",
    isAdmin: true
  }
}

const REGISTRATION_OPEN = false
const FLAG = process.env.FLAG || 'flag{redacted}'

const addUser = user => {
  if (Object.keys(users).includes(user.username) || user.isAdmin) {
    return
  }

  users[user.username] = {
    ...user,
    password: md5(user.password),
    isAdmin: false
  }
}

const checkPassword = (username, password) => {
  return users[username].password == md5(password)
}

const checkAdmin = username => {
  return users[username].isAdmin == true
}

app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'))
app.engine('handlebars', hbs.engine());
app.set('view engine', 'handlebars');
app.set('views', './views');

app.get("/", (req, res) => {
  res.render('index')
})

app.post("/register", (req, res) => {
  try {
    const { body } = req
    if (!REGISTRATION_OPEN) {
      res.send("Registration closed :(")
    }
    addUser(body)
    res.send("Success!")
  } catch {}
})

app.post("/get-flag", (req, res) => {
  try {
      const correctPassword = checkPassword(req.body.username, req.body.password)
      if (!correctPassword) {
        res.send("Bad password")
      }

      if (!checkAdmin(req.body.username)) {
        res.send("You are not admin")
      }

      res.send(FLAG)
  } catch {
    res.send("User not found")
  }
})

app.listen(5000)
