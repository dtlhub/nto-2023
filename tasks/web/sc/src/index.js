import express from "express"
import path from "path"

import visitURL from "./bot.js"

const FLAG = process.env.FLAG || "nto{dummy}"

const app = express()

app.use('/static', express.static(path.join(".", 'static')))


app.get("/report", async (req, res) => {
  const url = req.query.url
  if (typeof url !== "string") return res.send("url must be string")
  if (!url.startsWith("http://localhost:5000")) return res.send("url must starts with 'http://localhost:5000'")

  try {
    await visitURL(url)
  } catch {}

  res.send("Done!")
})

app.get("/flag", (req, res) => {
  const isLocal = req.connection.remoteAddress.endsWith("127.0.0.1")
  if (!isLocal) return res.send("nto{youshouldmakerequestfromlocalip}")
  return res.send(FLAG)
})

app.get("/", (req, res) => {
  res.sendFile(path.resolve('static/index.html'))
})



app.listen(5000)
