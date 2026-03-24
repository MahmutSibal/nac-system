# NAC Sistemi Teknik Raporu

## 1. Giris
Bu proje, kurum ici aglarda kimlik dogrulama, yetkilendirme ve hesap kaydi (AAA) sureclerini merkezi yonetmek icin tasarlanmis bir NAC (Network Access Control) cozumudur. Mimari, FreeRADIUS uzerinden gelen isteklerin FastAPI policy engine'e yonlendirilmesi ve bu katmanin PostgreSQL ile Redis kullanarak karar vermesi prensibine dayanir.

## 2. Mimari Ozeti
Sistem dort temel servisten olusur:
- FreeRADIUS 3.2: RADIUS protokol katmani, auth/accounting trafik girisi.
- FastAPI (Python 3.13): Policy engine; auth, authorize, accounting endpointleri.
- PostgreSQL 18: Kullanici, grup, VLAN policy ve muhasebe kayitlari.
- Redis 8: Rate-limiting ve aktif oturum cache katmani.

Veri akisi:
1. NAS cihazi, RADIUS Auth istegi gonderir.
2. FreeRADIUS authorize asamasinda FastAPI /authorize endpointini cagirir ve VLAN niteliklerini alir.
3. FreeRADIUS authenticate asamasinda FastAPI /auth endpointini cagirir; parola/MAB kontrolu ve rate-limit burada uygulanir.
4. Accounting paketleri FastAPI /accounting endpointiyle PostgreSQL radacct tablosuna yazilir, aktif oturumlar Redis'te tutulur.

## 3. Guvenlik Degerlendirmesi
### 3.1 Kimlik Bilgisi Saklama
Parolalar veritabaninda hash formatinda saklanir (MD5-Password ve opsiyonel Crypt-Password). Bilinen MAB kayitlari da cleartext yerine hash olarak tutulur. Uretim ortaminda bcrypt tabanli Crypt-Password tercih edilmelidir.

### 3.2 Brute-Force ve Abuse Koruma
Basarisiz giris denemeleri Redis uzerinde kullanici bazli sayac ile izlenir. Esik asildiginda belirli sure blok uygulanir. Bu mekanizma /auth endpointinde calistigi icin RADIUS authenticate akisinda da etkendir.

### 3.3 Ag ve Konfigurasyon Guvenligi
Hassas degerler .env uzerinden yonetilir ve git'e eklenmez. Servisler ozel docker aginda calisir. Veri kaybi riskini azaltmak icin PostgreSQL ve Redis volume ile kalici depolama kullanir.

## 4. Gercek Dunya Kullanim Senaryolari
### 4.1 Saglik Sektoru (Hastane Aglari)
- Klinik terminaller, medikal cihazlar ve ziyaretci agi farkli VLAN'lara ayrilir.
- Doktor/yonetim personeli daha yuksek yetki VLAN'larina gecis alirken, misafir cihazlar kisitli guest VLAN'da tutulur.
- Accounting kayitlari ile hangi cihazin ne zaman a baglandigi denetlenebilir.

### 4.2 Uretim ve Endustriyel Tesisler
- SCADA/OT cihazlari icin yalniz belirli cihaz kimliklerinin aga kabul edilmesi saglanir.
- Ofis personeli, saha personeli ve misafirler ayrik policy'lerle yonetilir.
- Oturum kayitlari, olay sonrasi adli analiz ve mevzuat uyumlulugu icin saklanir.
