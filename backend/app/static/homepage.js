window.addEventListener("load", function () {
    start = document.getElementById("start")
    event.preventDefault()
    fetch('/notes', { method: "get" })
        .then((response) => response.text())
        .then((text) => set_tabelka(text))
});


function send_tabelka() {
    var table = document.getElementById("output");
    var rows = table.getElementsByTagName("tr");
    var vals = [];
    for (var i = 0; i < rows.length - 1; i++) {
        var row = rows[i];
        var cols = row.getElementsByTagName("td");
        var vals2 = [];
        vals2.push(cols[0].id);
        for (var j = 0; j < cols.length; j++) {
            var col = cols[j];
            var inputs = col.getElementsByTagName("input");
            for (var k = 0; k < inputs.length; k++) {
                var input = inputs[k];
                if (input.type == "checkbox") {
                    if (input.checked) {
                        vals2.push("1");
                    } else {
                        vals2.push("0");
                    }
                }
            }
        }
        vals.push(vals2);
    }
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (xhr.readyState == XMLHttpRequest.DONE) {
            window.location.reload();
        }
    }
    xhr.open("POST", "/user/changeNotesSettings", true);
    xhr.setRequestHeader('Content-Type', 'application/json');
    xhr.send(JSON.stringify({
        value: vals
    }));
    return vals;
}

window.addEventListener("click", function () {
    start = document.getElementById("save_tabelka");
    start.onclick = function () { send_tabelka() };
});
