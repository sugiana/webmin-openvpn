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

    const proxyCheckbox = document.getElementById('proxy');
    const previewProxy = document.getElementById('previewProxy');

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

    if (proxyCheckbox && previewProxy) {
        function updateProxyPreview() {
            previewProxy.textContent = proxyCheckbox.checked ? 'proxy ' : '';
        }
        proxyCheckbox.addEventListener('change', updateProxyPreview);
        proxyCheckbox.addEventListener('click', updateProxyPreview);
    }

    // 3. User Table Live Search Filter
    const searchInput = document.getElementById('tableSearch');
    const usersTable = document.getElementById('usersTable');

    if (searchInput && usersTable) {
        searchInput.addEventListener('keyup', function() {
            const filter = searchInput.value.toLowerCase();
            const rows = usersTable.getElementsByTagName('tbody')[0].getElementsByTagName('tr');
            
            for (let i = 0; i < rows.length; i++) {
                const rowText = rows[i].textContent || rows[i].innerText;
                if (rowText.toLowerCase().indexOf(filter) > -1) {
                    rows[i].style.display = '';
                } else {
                    rows[i].style.display = 'none';
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

    // 5. Reverse Proxy Ports Modal & Input Restriction
    const proxyPortsForm = document.getElementById('proxyPortsForm');
    const portsInput = document.getElementById('reverseProxyPortsInput');
    const radioAll = document.getElementById('proxyPortModeAll');
    const radioCustom = document.getElementById('proxyPortModeCustom');
    const customWrapper = document.getElementById('customPortsWrapper');
    const portsFeedback = document.getElementById('portsErrorFeedback');

    if (proxyPortsForm && portsInput && radioAll && radioCustom) {
        // Enforce: User only types numbers and comma
        portsInput.addEventListener('keypress', function(e) {
            if (e.ctrlKey || e.metaKey || e.altKey) return;
            if (!/[0-9,]/.test(e.key)) {
                e.preventDefault();
            }
        });

        portsInput.addEventListener('input', function() {
            const cleaned = this.value.replace(/[^0-9,]/g, '');
            if (this.value !== cleaned) {
                this.value = cleaned;
            }
            if (portsInput.classList.contains('is-invalid')) {
                portsInput.classList.remove('is-invalid');
                if (portsFeedback) portsFeedback.style.display = 'none';
            }
        });

        function updatePortModeState() {
            if (radioCustom.checked) {
                portsInput.disabled = false;
                if (customWrapper) customWrapper.style.opacity = '1';
            } else {
                portsInput.disabled = true;
                if (customWrapper) customWrapper.style.opacity = '0.5';
                portsInput.classList.remove('is-invalid');
                if (portsFeedback) portsFeedback.style.display = 'none';
            }
        }

        radioAll.addEventListener('change', updatePortModeState);
        radioCustom.addEventListener('change', function() {
            updatePortModeState();
            portsInput.focus();
        });

        // Clicking or focusing on input selects Option 2 automatically
        portsInput.addEventListener('focus', function() {
            if (!radioCustom.checked) {
                radioCustom.checked = true;
                updatePortModeState();
            }
        });

        // Initialize state on load
        updatePortModeState();

        // Validate before submit
        proxyPortsForm.addEventListener('submit', function(e) {
            if (radioCustom.checked) {
                const val = portsInput.value.trim();
                if (!val) {
                    e.preventDefault();
                    portsInput.classList.add('is-invalid');
                    if (portsFeedback) {
                        portsFeedback.textContent = 'Harap masukkan nomor port (contoh: 6969,8081).';
                        portsFeedback.style.display = 'block';
                    }
                    portsInput.focus();
                    return false;
                }

                const portList = val.split(',').map(function(s) { return s.trim(); }).filter(function(s) { return s.length > 0; });
                if (portList.length === 0) {
                    e.preventDefault();
                    portsInput.classList.add('is-invalid');
                    if (portsFeedback) {
                        portsFeedback.textContent = 'Harap masukkan minimal satu port yang valid.';
                        portsFeedback.style.display = 'block';
                    }
                    portsInput.focus();
                    return false;
                }

                for (let i = 0; i < portList.length; i++) {
                    const portNum = parseInt(portList[i], 10);
                    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
                        e.preventDefault();
                        portsInput.classList.add('is-invalid');
                        if (portsFeedback) {
                            portsFeedback.textContent = 'Nomor port harus berada antara 1 dan 65535: ' + portList[i];
                            portsFeedback.style.display = 'block';
                        }
                        portsInput.focus();
                        return false;
                    }
                }
            }
            // Ensure input is not disabled upon form submit so value is included
            portsInput.disabled = false;
        });
    }

});
