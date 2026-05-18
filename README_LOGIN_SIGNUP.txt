PERUBAHAN LOGIN & SIGNUP WEBSECCHECK

File yang diubah/dibuat:
1. app/models.py
   - Menambahkan tabel users.
   - Menambahkan password_hash menggunakan Werkzeug, bukan password biasa.
   - Menambahkan user_id pada tabel scan_history agar riwayat scan terpisah per user.

2. app/routes.py
   - Login tidak lagi memakai ADMIN_USER dan ADMIN_PASS dari .env.
   - Menambahkan route /signup.
   - Login memakai data user dari database.
   - Riwayat scan, download PDF, dan hapus data dibatasi hanya untuk user yang sedang login.

3. app/templates/login.html
   - Tampilan login baru, umum, tanpa unsur Pemprov Sulut.

4. app/templates/signup.html
   - Halaman registrasi akun baru.

5. app/templates/index.html
   - Navbar dibuat umum.
   - Logo Sulut dihapus.
   - Riwayat yang tampil hanya milik user yang login.

6. app/templates/report_template.html
   - Footer dibuat umum.

7. docker-compose.yml
   - ADMIN_USER dan ADMIN_PASS dihapus.
   - Password database contoh diganti menjadi generik.

PENTING:
- Jika sebelumnya database sudah punya tabel scan_history lama tanpa user_id, buat database baru atau lakukan migrasi manual.
- Cara paling mudah saat development: hapus database lama lalu jalankan ulang aplikasi agar tabel baru dibuat otomatis.
- Akun user dibuat lewat halaman /signup.
