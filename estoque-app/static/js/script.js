function csrfToken() {
    return document.querySelector('meta[name="csrf-token"]').content;
}

function removeItem(id) {
    fetch(`/remove_item/${id}`, {
        method: 'POST',
        headers: { 'X-CSRFToken': csrfToken() }
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            window.location.reload();  // Recarrega a página
        } else {
            alert('Erro ao remover o item.');
        }
    });
}

function editItem(id) {
    const tipoText = document.getElementById(`tipo_text_${id}`);
    const tipoInput = document.getElementById(`tipo_input_${id}`);
    const tamanhoText = document.getElementById(`tamanho_text_${id}`);
    const tamanhoInput = document.getElementById(`tamanho_input_${id}`);
    const generoText = document.getElementById(`genero_text_${id}`);
    const generoInput = document.getElementById(`genero_input_${id}`);
    const quantText = document.getElementById(`quant_text_${id}`);
    const quantInput = document.getElementById(`quant_input_${id}`);
    const editButton = document.getElementById(`edit_button_${id}`);
    const row = document.getElementById(`row_${id}`);
    const rows = document.querySelectorAll('tbody tr');

    if (tipoInput.style.display === "none") {
        // Enter edit mode
        tipoText.style.display = "none";
        tipoInput.style.display = "inline";
        tamanhoText.style.display = "none";
        tamanhoInput.style.display = "inline";
        generoText.style.display = "none";
        generoInput.style.display = "inline";
        quantText.style.display = "none";
        quantInput.style.display = "inline";
        editButton.innerText = "Salvar Alterações";

        // Hide other rows
        rows.forEach(r => {
            if (r !== row) {
                r.style.display = "none";
            }
        });
    } else {
        // Save changes
        fetch(`/edit_item/${id}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken(),
            },
            body: JSON.stringify({
                tipo: tipoInput.value,
                tamanho: tamanhoInput.value,
                genero: generoInput.value,
                quantidade: quantInput.value
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Update text spans
                tipoText.innerText = tipoInput.value;
                tamanhoText.innerText = tamanhoInput.value;
                generoText.innerText = generoInput.value;
                quantText.innerText = quantInput.value;

                // Exit edit mode
                tipoText.style.display = "inline";
                tipoInput.style.display = "none";
                tamanhoText.style.display = "inline";
                tamanhoInput.style.display = "none";
                generoText.style.display = "inline";
                generoInput.style.display = "none";
                quantText.style.display = "inline";
                quantInput.style.display = "none";
                editButton.innerText = "Editar";

                // Show all rows
                rows.forEach(r => {
                    r.style.display = "table-row";
                });
            } else {
                alert('Erro ao editar o item.');
            }
        });
    }
}

