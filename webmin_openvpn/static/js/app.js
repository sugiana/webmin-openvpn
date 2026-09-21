document.addEventListener('DOMContentLoaded', function() {
    
    // 1. Password Visibility Toggle
    const togglePasswordBtn = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');
    const toggleIcon = document.getElementById('togglePasswordIcon');

    if (togglePasswordBtn && passwordInput && toggleIcon) {
        togglePasswordBtn.addEventListener('click', function() {
            const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
            passwordInput.setAttribute('type', type);
            toggleIcon.classList.toggle('bi-eye');
            toggleIcon.classList.toggle('bi-eye-slash');
        });
    }

    // 2. Real-time command preview in Create Cert page
    const usernameInput = document.getElementById('username');
    const previewUser = document.getElementById('previewUser');
    const previewPass = document.getElementById('previewPass');

    if (usernameInput && previewUser) {
        usernameInput.addEventListener('input', function() {
            const val = usernameInput.value.trim().toLowerCase();
            previewUser.textContent = val || '[username]';
        });
    }

    if (passwordInput && previewPass) {
        passwordInput.addEventListener('input', function() {
            previewPass.textContent = passwordInput.value ? '******' : '******';
        });
    }

    // 3. User Table Live Search Filter
    const searchInput = document.getElementById('tableSearch');
    const usersTable = document.getElementById('usersTable');

    if (searchInput && usersTable) {
        searchInput.addEventListener('keyup', function() {
            const filter = searchInput.value.toLowerCase();
            const rows = usersTable.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
            
            for (let i = 0; i < rows.length; i++) {
                const cells = rows[i].getElementsByTagName('td');
                if (cells.length > 1) {
                    const usernameText = cells[1].textContent || cells[1].innerText;
                    const emailText = cells[2].textContent || cells[2].innerText;
                    if (usernameText.toLowerCase().indexOf(filter) > -1 || emailText.toLowerCase().indexOf(filter) > -1) {
                        rows[i].style.display = '';
                    } else {
                        rows[i].style.display = 'none';
                    }
                }
            }
        });
    }

    // 4. Loading state on submit for long-running actions (e.g. create cert)
    const createCertForm = document.getElementById('createCertForm');
    const submitBtn = document.getElementById('submitBtn');

    if (createCertForm && submitBtn) {
        createCertForm.addEventListener('submit', function() {
            submitBtn.disabled = true;
            submitBtn.innerHTML = `
                <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                <span>Sedang Menjalankan build-client-cert...</span>
            `;
        });
    }

});
