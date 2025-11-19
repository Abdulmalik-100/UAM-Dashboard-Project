from flask import Flask, render_template, request, redirect, url_for, flash
import requests
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'

# بيانات تجريبية - سنستبدلها بـ RAM API لاحقاً
sample_users = [
    {"username": "user1", "policies": ["OSS-ReadOnly", "OSS-BucketA"]},
    {"username": "user2", "policies": ["OSS-FullAccess"]}
]

sample_policies = ["OSS-ReadOnly", "OSS-FullAccess", "OSS-BucketA", "OSS-BucketB"]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/users')
def users():
    return render_template('users.html', users=sample_users)

@app.route('/create-user', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        username = request.form['username']
        selected_policies = request.form.getlist('policies')
        
        # محاكاة لإنشاء المستخدم
        new_user = {
            "username": username,
            "policies": selected_policies
        }
        sample_users.append(new_user)
        
        flash(f'تم إنشاء المستخدم {username} بنجاح!', 'success')
        return redirect(url_for('users'))
    
    return render_template('create_user.html', policies=sample_policies)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True, use_reloader=False)