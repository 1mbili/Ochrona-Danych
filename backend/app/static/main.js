function set_tabelka(notes) {
    if (notes == null) notesObj = [];
    else notesObj = JSON.parse(notes);
    console.log(notesObj)
    table = document.getElementById("output")
    row = table.insertRow();
    table.setAttribute("class", "styled-table");
    main.appendChild(table);

    let html = "";
    var perrow = 1;
    notesObj.forEach((vals, i) => {
        cell = row.insertCell();
        cell.id = vals[0];
        text = `
        <div>
        <label class="tabela_label">${vals[1]}</label>
        <label>${vals[2]}</label>
        </div>
        `;
        cell.innerHTML = text
        cell2 = row.insertCell();
        text2 = `
        <div>
        <label class="tabela_label">Zaszyfruj</label>
        <input type="checkbox" id="checkbox_enc${i}"> 
        </div>
        `;
        cell2.innerHTML = text2
        var elem = document.getElementById(`checkbox_enc${i}`);
        if (vals[3] == "1") {
            elem.checked = true;
        }
        cell3 = row.insertCell();
        text3 = `
        <div>
        <label class="tabela_label">Udostępnij</label>
        <input type="checkbox" id="checkbox_share${i}"> 
        </div>
        `;
        cell3.innerHTML = text3
        var elem2 = document.getElementById(`checkbox_share${i}`);
        if (vals[4] == "1") {
            elem2.checked = true;
        }
        var next = i + 1;
        if (next % perrow == 0 && next != notes.length) { row = table.insertRow(); }
        });
}


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
    console.log(vals)
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
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


function myFunction() {
    var input, filter, table, tr, td, i, txtValue;
    input = document.getElementById("myInput");
    filter = input.value.toUpperCase();
    table = document.getElementById("output");
    table.setAttribute("class", "styled-table");
    tr = table.getElementsByTagName("tr");
    for (i = 0; i < tr.length; i++) {
      td = tr[i].getElementsByTagName("td")[0];
      if (td) {
        txtValue = td.textContent || td.innerText;
        if (txtValue.toUpperCase().indexOf(filter) > -1) {
          tr[i].style.display = "";
        } else {
          tr[i].style.display = "none";
        }
      }
    }
  }


  function set_public_tabelka(notes) {
    if (notes == null) notesObj = [];
    else notesObj = JSON.parse(notes);
    console.log(notesObj)
    table = document.getElementById("output")
    row = table.insertRow();
    table.setAttribute("class", "styled-table");
    main.appendChild(table);
    var perrow = 1;
    notesObj.forEach((vals, i) => {
        cell = row.insertCell();
        text = `
        <div>
        <label class="tabela_label">${vals[2]} - ${vals[1]}</label>
        </div>
        <div>
        <label>${vals[3]}</label>
        </div>
        `;
        cell.innerHTML = text
        var next = i + 1;
        if (next % perrow == 0 && next != notes.length) { row = table.insertRow(); }
        });
}