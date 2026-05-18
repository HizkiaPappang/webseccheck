from urllib.parse import urlparse
from flask import Blueprint, render_template, request, redirect, url_for, make_response, flash
from flask_login import login_user, logout_user, login_required, current_user
from app import db, login_manager
from app.models import ScanHistory, User
from modules.scanner import perform_scan
from weasyprint import HTML

main = Blueprint('main', __name__)


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except (TypeError, ValueError):
        return None


@main.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip().lower()
        password = request.form.get('password') or ''
        confirm_password = request.form.get('confirm_password') or ''

        if not username or not email or not password:
            flash('Semua field wajib diisi.', 'danger')
            return redirect(url_for('main.signup'))

        if len(password) < 6:
            flash('Password minimal 6 karakter.', 'warning')
            return redirect(url_for('main.signup'))

        if password != confirm_password:
            flash('Konfirmasi password tidak sama.', 'warning')
            return redirect(url_for('main.signup'))

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username atau email sudah digunakan.', 'danger')
            return redirect(url_for('main.signup'))

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Akun berhasil dibuat. Silakan login.', 'success')
        return redirect(url_for('main.login'))

    return render_template('signup.html')


@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    if request.method == 'POST':
        identity = (request.form.get('identity') or '').strip()
        password = request.form.get('password') or ''

        user = User.query.filter((User.username == identity) | (User.email == identity.lower())).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login berhasil.', 'success')
            return redirect(url_for('main.index'))

        flash('Login gagal. Username/email atau password salah.', 'danger')

    return render_template('login.html')


@main.route('/')
@login_required
def index():
    user_scans = ScanHistory.query.filter_by(user_id=current_user.id)
    recent_scans = user_scans.order_by(ScanHistory.timestamp.desc()).all()

    stats = {
        'critical': user_scans.filter_by(overall_risk='Critical').count(),
        'high': user_scans.filter_by(overall_risk='High').count(),
        'medium': user_scans.filter_by(overall_risk='Medium').count(),
        'low': user_scans.filter_by(overall_risk='Low').count(),
        'info': user_scans.filter(ScanHistory.overall_risk.in_(['Informational', 'Aman'])).count(),
    }

    return render_template('index.html', scans=recent_scans, stats=stats)


@main.route('/scan', methods=['POST'])
@login_required
def scan_process():
    target_url = (request.form.get('url') or '').strip()

    if not target_url:
        flash('Kolom URL tidak boleh kosong.', 'danger')
        return redirect(url_for('main.index'))

    if not target_url.startswith(('http://', 'https://')):
        flash('Format URL harus diawali http:// atau https://', 'warning')
        return redirect(url_for('main.index'))

    parsed_url = urlparse(target_url)
    if not parsed_url.netloc:
        flash('Domain URL tidak valid.', 'danger')
        return redirect(url_for('main.index'))

    try:
        result = perform_scan(target_url)
        if not result:
            flash('Sistem gagal melakukan pemindaian pada target.', 'danger')
            return redirect(url_for('main.index'))

        vuln_text = str(result.get('vulnerabilities', ''))
        if len(vuln_text) > 60000:
            vuln_text = vuln_text[:60000] + '... (Dipotong karena terlalu panjang)'

        new_scan = ScanHistory(
            user_id=current_user.id,
            target_url=target_url,
            overall_risk=str(result.get('overall_risk', 'Unknown')),
            vulnerabilities=vuln_text,
        )
        db.session.add(new_scan)
        db.session.commit()
        flash('Scan selesai dan riwayat berhasil disimpan.', 'success')

    except Exception as e:
        db.session.rollback()
        print(f'[ERROR] Gagal melakukan scan/simpan data: {e}', flush=True)
        flash(f'Terjadi kesalahan internal: {e}', 'danger')

    return redirect(url_for('main.index'))


@main.route('/report/<int:scan_id>')
@login_required
def download_report(scan_id):
    scan_data = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    rendered_html = render_template('report_template.html', scan=scan_data)
    pdf = HTML(string=rendered_html).write_pdf()

    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    clean_name = scan_data.target_url.replace('https://', '').replace('http://', '').replace('/', '_')
    response.headers['Content-Disposition'] = f'attachment; filename=Laporan_{clean_name}.pdf'
    return response


@main.route('/delete/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = ScanHistory.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    db.session.delete(scan)
    db.session.commit()
    flash('Data riwayat pemindaian berhasil dihapus.', 'success')
    return redirect(url_for('main.index'))


@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Anda berhasil logout.', 'info')
    return redirect(url_for('main.login'))
