Pemasangan OpenVPN
==================

Ini sudah dicoba dengan Debian 13.

Pasang paket Debian::

    sudo apt install openvpn iptables

Unduh script pembuat sertifikat server::

    wget -O build-server-cert.sh https://git.opensipkd.com/snippets/39/raw

Siapkan passphrase yaitu password untuk membuat sertifikat, boleh sama dengan
password SSH. Lalu buat sertifikatnya::

    sudo sh build-server-cert.sh 10.8.41.0

Segment IP boleh yang lain:

1. Harus berakhiran nol.
2. Sebaiknya tetap berawalan ``10.8.``, contoh: ``10.8.42.0``

Buat file ``/etc/sysctl.d/ip_forward.conf``::

    net.ipv4.ip_forward=1

Ini agar PC dapat diakses dari Internet.

Siapkan direktori untuk script yang akan dijalankan saat VPN client up dan down::

    sudo mkdir /etc/openvpn/server/script

Buat file ``/etc/openvpn/server/script/client-up``::

    #!/bin/sh
    iptables -t nat -A POSTROUTING -j MASQUERADE -s $ifconfig_pool_remote_ip
    iptables -t nat -I PREROUTING -p tcp -d 202.43.164.162 -m multiport ! --dports 22,80,443,1194 -j DNAT --to-destination $ifconfig_pool_remote_ip
    exit 0

Sesuaikan IP itu dengan IP publik server ini.

Buat file ``/etc/openvpn/server/script/client-down``::

    #!/bin/sh
    iptables -t nat -D POSTROUTING -j MASQUERADE -s $ifconfig_pool_remote_ip
    iptables -t nat -D PREROUTING -p tcp -d 202.43.164.162 -m multiport ! --dports 22,80,443,1194 -j DNAT --to-destination $ifconfig_pool_remote_ip
    exit 0

Buat file ``/etc/openvpn/server/script/check-auth`` untuk memastikan user yang
login sesuai sertifikat::

    #!/bin/bash
    # OpenVPN menyediakan file kredensial via $1 jika via-file digunakan,
    # atau membaca environment variable jika via-env digunakan.
    # Membaca username yang dimasukkan klien
    if [ -n "$1" ] && [ -f "$1" ]; then
        auth_user=$(head -n 1 "$1")
    else
        auth_user="$username"
    fi
    # Validasi: Common Name sertifikat ($common_name) wajib sama persis dengan username
    if [ -z "$common_name" ] || [ "$common_name" != "$auth_user" ]; then
        echo "AUTH REJECTED: Certificate CN '$common_name' does not match username '$auth_user'" >&2
        exit 1
    fi
    exit 0

Jadikan semuanya executable::

    sudo chmod +x /etc/openvpn/server/script/*

Tambahkan di ``/etc/openvpn/server.conf``::

    script-security 3
    client-connect /etc/openvpn/server/script/client-up
    client-disconnect /etc/openvpn/server/script/client-down
    plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
    auth-user-pass-verify /etc/openvpn/server/script/check-auth via-file

Baris terakhir itu untuk mewajibkan user memasukkan username dan password.

Reboot agar aktif, juga untuk memastikan apakan VPN server otomatis hidup.


Sertifikat Client
-----------------

Simpan passphrase tadi di ``/etc/openvpn/server/passphrase.txt``. Pastikan
hanya bisa dibaca oleh pemiliknya yaitu root::

    sudo chmod g-rw,o-rw /etc/openvpn/server/passphrase.txt

File ini dibutuhkan oleh script pembuat sertifikat client agar kita tak perlu
repot mengetikkannya.

Unduh script-nya::

    sudo wget -O /usr/local/bin/build-client-cert https://git.opensipkd.com/snippets/40/raw
    sudo chmod +x /usr/local/bin/build-client-cert

Jalankan dengan pola::

    sudo build-client-cert <nama-client> [login] [proxy] [adduser] [pass=<password>]

Penjelasan:

1. ``<nama-client>`` ini bebas, tapi sebaiknya hanya huruf, angka, dan karakter minus.
2. ``[login]`` bila server mewajibkan login
3. ``[proxy]`` bila server sebagai proxy
4. ``[adduser]`` untuk membuat user ``<nama-client>``. Ini adalah user Linux
   yang terdaftar di file ``/etc/passwd``.
5. ``[pass=<password>]`` ini password untuk poin 5. Jika tidak disertakan maka
   akan ditanya saat pembuatan (mode interaktif). 
   
Contoh::

    sudo build-client-cert sugiana login proxy adduser pass=G4do-gado

Selanjutnya sertifikat ada di direktori ``/etc/openvpn/client``. Salinannya ada
di ``/root`` untuk memudahkan ``scp``.


Multi Client
------------

Konfigurasi ``server.conf`` sebelumnya beranggapan hanya ada 1 client. Meskipun
ada client ke-2, ke-3, dst maka client terakhir yang mendapat reverse proxy.

Untuk itu kini kita tetapkan hanya username yang tercatat di file
``/var/log/openvpn/proxy.txt`` saja yang mendapat reverse proxy maupun akses
proxy biasa (forward proxy). Client lain tetap dapat saling terhubung dengan
akses Internet dari ISP masing-masing.

File ini berisi sebuah username, misalkan ``sugiana``. Ini bisa diisi
dengan cara::

    sudo su
    echo sugiana > /var/log/openvpn/proxy.txt

Jika reverse proxy hanya port tertentu maka::

    echo sugiana:7070,6543

Kemudian file ``/etc/openvpn/server/script/client-up`` berisi ini::

    #!/bin/sh
    PROXY_FILE="/var/log/openvpn/proxy.txt"
    if [ -f $PROXY_FILE ]; then
        USER=$(cat $PROXY_FILE | awk -F':' '{print $1}')
        if [ "$common_name" = "$USER" ]; then
            PORTS=$(cat $PROXY_FILE | awk -F':' '{print $2}')
            /usr/local/bin/new-proxy-user $ifconfig_pool_remote_ip $PORTS
        fi
    fi

Salin file untuk menjalankan ``iptables``::

    sudo cp new-proxy-user /usr/local/bin/

Hapus baris ``client-disconnect`` di ``/etc/openvpn/server.conf`` sehingga menjadi::

    script-security 3
    client-connect /etc/openvpn/server/script/client-up
    plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
    auth-user-pass-verify /etc/openvpn/script/check-auth via-file

Restart::

    sudo systemctl restart openvpn@server

Semoga dipahami.
