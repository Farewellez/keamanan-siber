# Main Quest 1: Latihan Analisis Lalu Lintas Jaringan

### A. Ringkasan Eksekutif
Telah terdeteksi aktivitas anomali jaringan yang mengindikasikan adanya infeksi malware jenis NetSupport RAT di dalam segmen LAN 10.2.28.0/24. Infeksi ini melakukan komunikasi Command and Control (C2) ke server eksternal dengan menyamarkan lalu lintas HTTP biasa melalui Port 443.

### B. Identifikasi Host Terinfeksi (Victim)
Berdasarkan analisis log PCAP, satu komputer di dalam domain EASYAS123 telah terkompromi. Untuk PoC analisis disini menggunakan gabungan wireshark dan tshark. Jadi via CLI tanpa GUI agar mempermudah pengerjaan dan analisis dengan bantuan AI:

#### IP Address: 10.2.28.88
Melalui deskripsi analisis traffic di wireshark, ip yang cukup aktif bisa dilihat yaitu 10.2.28.88. kita bisa melihat aktivitas lalu lintas jaringan diinisiasi oleh satu alamat IP klien dari dalam segmen LAN tersebut. 

IP ini melakukan banyak aktivitas seperti request DHCP (Paket 2), request ARP (Paket 3 & 5), kueri DNS (Paket 7), hingga berbagai koneksi TCP/TLS ke server luar.

Alamat IP klien yang sangat aktif tersebut adalah 10.2.28.88. Karena ini adalah satu-satunya host di dalam rentang LAN yang terlihat lalu lintasnya berpotensi memicu alert ke IP berbahaya, kita bisa menetapkannya sebagai IP host yang terinfeksi.
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/12942205-5c10-41bd-afb9-985bc8d6d85e" />

#### MAC Address: 00:19:d1:b2:4d:ad
Command ini mengambil MAC Address source dari paket pertama yang dikirimkan oleh IP 10.2.28.88
```bash
sekai/college/keamanan-siber 
❯ tshark -r lalu_lintas_jaringan.pcap -Y "ip.src == 10.2.28.88 and eth.src" -T fields -e eth.src | sort | uniq | head -n 1
00:19:d1:b2:4d:ad

```

#### Hostname: DESKTOP-TEYQ2NR

Command ini memfilter paket NetBIOS Name Service (NBNS) dari IP korban untuk melihat nama komputer yang di-broadcast.

```bash
sekai/college/keamanan-siber 
❯ tshark -r lalu_lintas_jaringan.pcap -Y "nbns and ip.src == 10.2.28.88" -T fields -e nbns.name | head -n 1
DESKTOP-TEYQ2NR<20>,DESKTOP-TEYQ2NR<20> (Server service)

```

#### User Account: brolf

Command ini mengambil field CNameString dari paket autentikasi Kerberos yang dikirimkan klien ke Domain Controller.

```bash
sekai/college/keamanan-siber 
❯ tshark -r lalu_lintas_jaringan.pcap -Y "kerberos.CNameString and ip.src == 10.2.28.88" -T fields -e kerberos.CNameString | head -n 1
brolf

```

Kita berhasil mengamankan tiga informasi identitas:

* Mac Address: `00:19:d1:b2:4d:ad`
* Hostname: `DESKTOP-TEYQ2NR`
* User Account: `brolf`

### C. Indikator Kompromi (Indicator of Compromise / IoC)

Aktivitas berbahaya diinisiasi menuju infrastruktur peretas. Berikut adalah rekam jejak identifikasi parameter serangannya menggunakan `tshark`:

#### 1. IP Address C2 & Malicious URL

Mengekstrak seluruh permintaan HTTP dari IP korban untuk mencari anomali trafik *beaconing*. Terlihat kueri mencurigakan secara repetitif (berulang-ulang) ke sebuah IP publik tanpa nama domain.

```bash
sekai/college/keamanan-siber 
❯ tshark -r lalu_lintas_jaringan.pcap -Y "http.request and ip.src == 10.2.28.88" -T fields -e http.host -e http.request.uri | grep 45.131.214.85 | head -n 3
45.131.214.85    [http://45.131.214.85/fakeurl.htm](http://45.131.214.85/fakeurl.htm)
45.131.214.85    [http://45.131.214.85/fakeurl.htm](http://45.131.214.85/fakeurl.htm)
45.131.214.85    [http://45.131.214.85/fakeurl.htm](http://45.131.214.85/fakeurl.htm)

```

* **IP Address C2**: `45.131.214.85`
* **Malicious URI**: `http://45.131.214.85/fakeurl.htm`

#### 2. User-Agent

Mengekstrak *header User-Agent* dari trafik HTTP menuju IP peretas. *User-Agent* ini menjadi indikator kuat (*signature hit*) dari jenis *malware* yang digunakan.

```bash
sekai/college/keamanan-siber 
❯ tshark -r lalu_lintas_jaringan.pcap -Y "http.request and ip.dst == 45.131.214.85" -T fields -e http.user_agent | sort | uniq
NetSupport Manager/1.3

```

* **Malware Family**: NetSupport RAT

#### 3. Destination Port

Mengekstrak *port* TCP yang dituju. Komunikasi HTTP biasa dikirimkan melalui *port* 443, yang merupakan teknik *evasion* untuk mengelabui *firewall* agar seolah-olah terlihat sebagai trafik HTTPS terenkripsi.

```bash
sekai/college/keamanan-siber 
❯ tshark -r lalu_lintas_jaringan.pcap -Y "ip.dst == 45.131.214.85 and tcp" -T fields -e tcp.dstport | sort | uniq
443

```

* **Port Tujuan**: `443` (TCP)

#### 4. Pola Serangan & Eksfiltrasi Data (Payload)

Klien awalnya secara aktif melakukan *beaconing* menggunakan HTTP GET, lalu beralih menggunakan HTTP POST untuk mengeksfiltrasi data atau merespons perintah peretas. Variabel `CMD=ENCD` membuktikan bahwa komunikasi C2 ini telah dienkripsi.

```bash
sekai/college/keamanan-siber 
❯ tshark -r lalu_lintas_jaringan.pcap -Y "http.request.method == POST and ip.dst == 45.131.214.85" -T fields -e http.file_data -e urlencoded-form.value | head -n 3
434d443d504f4c4c0a494e464f3d310a41434b3d310a    POLL\nINFO=1\nACK=1\n
434d443d454e43440a45533d310a444154413d75fe...   
434d443d454e43440a45533d310a444154413d6c33...   ENCD\nES=1\nDATA=l3<(T{EVk9|||$(m$Cj_и0MtsM6\n

```

### D. Rekomendasi Mitigasi (Action Plan)

Untuk menghentikan aktivitas berbahaya ini, pihak terkait harus segera:

1. **Network Isolation:** Memblokir IP C2 (`45.131.214.85`) pada tingkat Firewall/Gateway (`10.2.28.1`).
2. **Host Containment:** Memutus komputer `DESKTOP-TEYQ2NR` dari jaringan lokal untuk mencegah pergerakan lateral (*lateral movement*).
3. **Remediasi:** Melakukan *scanning* menyeluruh menggunakan Antivirus/EDR untuk menghapus instalasi NetSupport RAT.
4. **Credential Reset:** Mereset *password* akun Active Directory milik user `brolf` (`10.2.28.2`).
