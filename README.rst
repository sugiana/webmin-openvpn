Webmin OpenVPN Management Portal
================================

Aplikasi web manajemen OpenVPN berbasis `Pyramid Framework <https://trypyramid.com/>`_,
template `Chameleon <https://pypi.org/project/Chameleon>`_,
antarmuka `Bootstrap 5 <https://getbootstrap.com/>`_,
ORM `SQLAlchemy <https://pypi.org/project/SQLAlchemy/>`_,
tabel hak akses `Ziggurat-Foundations <https://pypi.org/project/ziggurat-foundations/>`_,
dan database `PostgreSQL <https://postgresql.org>`_.

**PERHATIAN**

Sebelum menggunakan ini pastikan mengikuti langkah `Pemasangan OpenVPN <pemasangan-openvpn.rst>`_. 


Fitur Utama
-----------

1. Menu

   - Menjalankan perintah sistem untuk membuat sertifikat VPN client: ``build-client-cert [username] proxy login adduser pass=[password]``.
   - Mengunduh sertifikat
   - Mengubah password user Linux

2. Keamanan & Database

   - Password di database dienkripsi menggunakan standar password hashing aman (``PBKDF2-SHA256` / `Bcrypt``) via Ziggurat Foundations.
   - Autentikasi berbasis cookie tiket aman (``pyramid.authentication.AuthTktCookieHelper``).
   - Kontrol hak akses berbasis peran (*Role-Based Access Control* / ACL) dengan pemisahan prefix ``/admin`` untuk grup ``admin`` dan root ``/`` untuk grup ``publik``.


Panduan Menjalankan Aplikasi
----------------------------

Pasang Postgres::

    sudo apt install postgresql

Buat usernya::

    sudo su - postgres
    createuser -P sugiana 

Buat database::

    createdb -O sugiana openvpn
    exit

Buat Python virtual environment::

    python3.13 -m venv ~/env

Unduh aplikasi ini::

    git clone https://github.com/sugiana/webmin-openvpn

Pasang::

    ~/env/bin/pip install webmin-openvpn 

Salin contoh file konfigurasi::

    cp webmin-openvpn/production.ini .

Di ``production.ini`` ubah baris ``sqlalchemy.url`` sesuai dengan user,
password, dan nama database yang tadi dibuat. Bila perlu sesuaikan juga baris
``auth.secret`` dan ``session.secret`` dengan rangkaian kalimat acak yang Anda
anggap aman. Lalu buat tabel-tabelnya::

    ~/env/bin/initialize_webmin_openvpn_db production.ini 

Default akun administrator yang dibuat:

- **Username**: ``admin``
- **Password**: ``admin``

Buat file ``/etc/systemd/system/webmin-openvpn.service``::

    [Unit]
    After=postgreql.service

    [Service]
    Type=simple
    ExecStart=/home/sugiana/env/bin/pserve /home/sugiana/production.ini

    [Install]
    WantedBy=multi-user.target

Jalankan server::

    sudo systemcl daemon-reload
    sudo systemctl enable webmin-openvpn.service
    sudo systemctl start webmin-openvpn.service

Aplikasi akan berjalan di: ``http://localhost:6543``.


Pengaturan Nginx
----------------

Aplikasi itu akan diakses oleh Nginx sebagai web server utama. Buatlah sertifikat SSL-nya::

    sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt

Pasang Nginx::

    sudo apt install nginx

Sesuaikan file ``/etc/nginx/sites-available/default`` menjadi::

    server {
        listen 80 default_server;
        listen [::]:80 default_server;
        return 301 https://$host$request_uri;
    }
    server {
        listen 443 ssl;
        ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
        ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
        client_max_body_size 100M;
        client_body_timeout 1800s;
        client_header_timeout 60s;
        send_timeout 1800s;
        keepalive_timeout 65s;
        location / {
            proxy_pass http://127.0.0.1:6543;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;
            proxy_set_header Connection "";
            proxy_redirect off;
            proxy_connect_timeout 60s;
            proxy_read_timeout 1800s;
            proxy_send_timeout 1800s;
            proxy_request_buffering off;
            proxy_buffering off;
        }
        location /static/ {
            root /home/sugiana/webmin-openvpn/webmin_openvpn;
        }
    }

Daftarkan user ``www-data`` ke grup ``sugiana`` agar ia bisa membaca *static files*::

    sudo adduser www-data sugiana

Sesuaikan hak akses::

    sudo chmod 750 /home/sugiana

Restart Nginx::

    sudo systemctl restart nginx

Cobalah di Chrome sesuai dengan IP publiknya.


Menjalankan Pengujian
---------------------

Ini dilakukan selama masa uji coba. Untuk menjalankan rangkaian pengujian otomatis::

    cd webmin-openvpn

Pasang modul-modul terkait pengujian::

    ~/env/bin/pip install -e ".[testing]"

Buatlah file konfigurasinya::

    cp development.ini test.ini

Di file ``test.ini`` sesuaikan baris ``sqlalchemy.url``, lalu::

    ~/env/bin/pytest -v

Pastikan semua pengujian berakhiran ``PASSED``, tidak ada ``FAILED``.
