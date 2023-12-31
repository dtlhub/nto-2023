# Lambda Calculus

_Author: [@LeKSuS-04](https://github.com/LeKSuS-04)_

> Любишь математику? Тогда перечисли все функции!

## Решение

В выданном участникам файле записано выражение на языке Lambda Calculus. На это намекают название и описание таска; а также к этому можно придти, заметив в содержимом файла символ "λ" (лямбда) и погуглив нечто похожее на "lambda functions math". Узнав язык, почитать как он работает можно, например, здесь:
- [Learn X in Y minutes](https://learnxinyminutes.com/docs/lambda-calculus/)
- [Stanford Encyclopedia of Philosophy](https://plato.stanford.edu/entries/lambda-calculus/)

На самом деле, даже не требовалось определять, что в файле содержится нотация Lambda Calculus. Язык достаточно прост и представляет из себя последовательное применение функций, так что до смысла происходящего можно было просто догадаться.

После более тщательной экзаменации содержимого файла, можно разбить его компоненты на три типа:
- Entity: `<Lambda> | <Variable> | <Value>`
- Lambda: `(λ<Variables>.<Entities>)`
- Variable: `([a-zA-Z0-9]{4})`
- Value: `('<ASCII-symbol>')`

Применение лямбда-функции к некоторому числу аргументов выглядит следующим образом:
- Application: `<Lambda><Entities>`

Разобравшись в этом, остается только запрограммировать решение указанного выражения. Пример сплойта лежит в [sploit/sploit.py](./sploit/sploit.py).

_* Автор допускает, что, при достаточном упорстве и стойкости духа, таск можно решить не автоматизируя решение. Но автоматизированное решение точно возможно, так что это не имеет значения._
