function set_tabelka(notes) {
    if (notes === null) notesObj = [];
    else notesObj = JSON.parse(notes);
    table = document.getElementById("output")
    row = table.insertRow();
    table.setAttribute("class", "styled-table");
    main.appendChild(table);
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
        <label class="tabela_label">Zaszyfruj/Odszyfruj</label>
        <input type="password" id="checkbox_enc${i}"> 
        </div>
        `;
        cell2.innerHTML = text2
        cell3 = row.insertCell();
        text3 = `
        <div>
        <label class="tabela_label">Udostępnij</label>
        <input type="checkbox" id="checkbox_share${i}"> 
        </div>
        `;
        cell3.innerHTML = text3
        var elem2 = document.getElementById(`checkbox_share${i}`);
        if (vals[3] == "1") {
            elem2.checked = true;
        }
        var next = i + 1;
        if (next % perrow == 0 && next != notes.length) { row = table.insertRow(); }
    });
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

window.addEventListener("click", function () {
    search_bar = document.getElementById("myInput");
    search_bar.onkeyup = function () { myFunction() };
})


function set_public_tabelka(notes) {
    if (notes === null) notesObj = [];
    else notesObj = JSON.parse(notes);
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