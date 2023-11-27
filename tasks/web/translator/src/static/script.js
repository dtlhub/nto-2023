const translateInput = document.querySelector("textarea.translate--input")
const params = new URL(window.location).searchParams

translateInput.value = params.get("q")

