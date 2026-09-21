Pemasangan OpenVPN
==================

Ini sudah dicoba dengan Debian 13.

Pasang paket Debian::

    sudo apt install openvpn

Unduh script pembuat sertifikat server::

    wget -O build-server-cert.sh https://git.opensipkd.com/snippets/39/raw

Siapkan passphrase yaitu password untuk membuat sertifikat, boleh sama dengan
password SSH. Lalu buat sertifikatnya::

    sudo sh build-server-cert.sh vpn-server 10.8.41.0

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
    iptables -t nat -I PREROUTING -p tcp -d 202.43.164.162 -m multiport ! --dports 22,1194 -j DNAT --to-destination $ifconfig_pool_remote_ip
    exit 0

Sesuaikan IP itu dengan IP publik server ini.

Buat file ``/etc/openvpn/server/script/client-down``::

    #!/bin/sh
    iptables -t nat -D POSTROUTING -j MASQUERADE -s $ifconfig_pool_remote_ip
    iptables -t nat -D PREROUTING -p tcp -d 202.43.164.162 -m multiport ! --dports 22,1194 -j DNAT --to-destination $ifconfig_pool_remote_ip
    exit 0

Jadikan keduanya executable::

    sudo chmod +x /etc/openvpn/server/script/client-up
    sudo chmod +x /etc/openvpn/server/script/client-down

Tambahkan di ``/etc/openvpn/server.conf``::

    script-security 3
    client-connect /etc/openvpn/server/script/client-up
    client-disconnect /etc/openvpn/server/script/client-down
    plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login

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

    sudo build-client-cert <nama-client> <ip-publik> [login] [proxy] [adduser] [pass=<password>]

Penjelasan:

1. ``<nama-client>`` ini bebas, tapi sebaiknya hanya huruf, angka, dan karakter minus.
2. ``<ip-publik>`` adalah IP saat kita ssh ke server ini.
3. ``[login]`` bila server mewajibkan login
4. ``[proxy]`` bila server sebagai proxy
5. ``[adduser]`` untuk membuat user ``<nama-client>``. Ini adalah user Linux
   yang terdaftar di file ``/etc/passwd``.
6. ``[pass=<password>]`` ini password untuk poin 5. Jika tidak disertakan maka
   akan ditanya saat pembuatan (mode interaktif). 
   
Contoh::

    sudo build-client-cert sugiana 202.43.164.162 login proxy adduser pass=G4do-gado

Selanjutnya sertifikat ada di direktori ``/etc/openvpn/client``. Salinannya ada
di ``/root`` untuk memudahkan ``scp``.

Untuk sertifikat berikutnya tak perlu menyebutkan IP karena template
``/etc/openvpn/server/client.ovpn`` sudah terbentuk::

    sudo build-client-cert pc1 login proxy adduser pass=K4redok

Semoga dipahami.
