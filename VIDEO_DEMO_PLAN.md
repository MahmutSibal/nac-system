# NAC Proje Videosu Cekim Plani (10-15 dk)

## Hedef
Bu belge, istenen video teslimatini hizli ve eksiksiz hazirlamak icin sahne bazli bir akistir.

## Toplam Sure
- Hedef: 12 dakika
- Format: MP4 veya YouTube unlisted link
- Dil: Turkce veya Ingilizce

## Sahne Akisi
1. Giris ve Mimari (2 dk)
- Ekranda docker-compose yapisini goster.
- FreeRADIUS -> FastAPI -> PostgreSQL/Redis akis diyagramini anlat.

2. Ortam Kurulumu (2 dk)
- .env.example dosyasini goster.
- docker compose up -d --build komutunu calistir.
- docker compose ps ile tum servislerin healthy oldugunu goster.

3. Authentication Testleri (3 dk)
- Basarili PAP girisi (admin/employee/guest).
- Basarisiz parola denemesi.
- MAB testi (bilinen MAC ve fallback MAC).

4. Authorization Testleri (2 dk)
- /authorize cagrisi veya radtest ciktilarinda Tunnel-Type/Tunnel-Private-Group-Id goster.
- admin=VLAN10, employee=VLAN20, guest=VLAN30 eslesmesini acikla.

5. Accounting ve Oturumlar (2 dk)
- Start/Interim/Stop paketlerini radclient ile gonder.
- PostgreSQL radacct kaydini sorgulayip goster.
- Redis aktif oturum listesini API uzerinden goster.

6. Guvenlik ve Kapanis (1 dk)
- Rate-limiting mekanizmasini canli goster.
- Secret yonetimi (.env), hash saklama, izlenebilirlik maddelerini ozetle.

## Cekim Kontrol Listesi
- Mikrofon sesi net mi?
- Terminal fontu okunur mu?
- Komutlar hata vermeden calisiyor mu?
- Her test senaryosu ekranda gorunuyor mu?
- Son videoda sure 10-15 dk araliginda mi?
