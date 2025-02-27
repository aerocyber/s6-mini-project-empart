from flask import Blueprint, request, render_template, redirect
from db import AdminDB
import re

admin_setup = Blueprint('admin_setup', __name__)

@admin_setup.route('/setup', methods=['POST', 'GET'])
def setup():
    adminDb = AdminDB()
    if request.method == 'POST':
        admin_email = request.form['admin_email'] or None
        admin_password = request.form['admin_password'] or None
        confirm_password = request.form['confirm_password'] or None

        if admin_password != confirm_password:
            return render_template('admin_setup.html', error='Passwords do not match')
        
        p = r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,}$'
        if not re.match(p, admin_password):
            return render_template('admin_setup.html', error='Invalid format for password')

        if adminDb.get_count() > 0:
            return redirect('/admin/login')
        adminDb.add_admin(admin_email, admin_password)
        return redirect('/admin/login')
    if adminDb.get_count() > 0:
        return redirect('/admin/login')
    return render_template('admin_setup.html')