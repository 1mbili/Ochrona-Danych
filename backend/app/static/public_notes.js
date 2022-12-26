window.addEventListener("load", function () {
    start = document.getElementById("start")
    event.preventDefault()
    fetch('/public_notes', { method: "get" })
        .then((response) => response.text())
        .then((text) => set_public_tabelka(text))
});