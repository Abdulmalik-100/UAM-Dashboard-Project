from flask import Flask, render_template, flash, request, redirect, url_for, get_flashed_messages, session
from aliyunsdkcore.client import AcsClient
from aliyunsdkram.request.v20150501 import (
    ListUsersRequest, ListPoliciesForUserRequest, CreateUserRequest, DeleteUserRequest,
    AttachPolicyToUserRequest, DetachPolicyFromUserRequest,
    ListGroupsRequest, CreateGroupRequest, DeleteGroupRequest, AddUserToGroupRequest, ListGroupsForUserRequest,
    AttachPolicyToGroupRequest, ListPoliciesForGroupRequest, DetachPolicyFromGroupRequest,
    ListRolesRequest, CreateRoleRequest, GetRoleRequest, UpdateRoleRequest, DeleteRoleRequest,
    CreateAccessKeyRequest
)
from aliyunsdksts.request.v20150401 import AssumeRoleRequest, GetCallerIdentityRequest
import csv
import io
from aliyunsdkcore.acs_exception.exceptions import ClientException, ServerException
import json
import time
import datetime
import os
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

# --- إعدادات التطبيق ---
REGION_ID = "cn-hangzhou"
app = Flask(__name__)
app.secret_key = 'SECRET_KEY_HERE'
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0 
API_READ_TIMEOUT = 60
API_CONNECT_TIMEOUT = 60

# --- تعريف الصلاحيات ---
AVAILABLE_POLICIES = {
    "AdministratorAccess": "صلاحيات كاملة (Admin)",
    "ReadOnlyAccess": "قراءة فقط (Read-Only)",
    "AliyunECSFullAccess": "تحكم كامل بـ ECS",
    "AliyunRDSFullAccess": "تحكم كامل بـ RDS",
    "AliyunRAMFullAccess": "تحكم كامل بـ RAM",
    "AliyunSLBFullAccess": "تحكم كامل بـ SLB",
    "PowerUserAccess": "صلاحيات قوية (بدون إدارة مستخدمين)",
    "Allow-STS-Assume-Role": "صلاحية STS المخصصة" 
}

TRUST_POLICY_TEMPLATES = {
    "ecs_role": {
        "display": "سيرفرات ECS",
        "policy_document": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"ecs.aliyuncs.com\"]}}],\"Version\":\"1\"}"
    },
    "user_role": {
        "display": "مستخدمين (RAM User)",
        "policy_document": "{\"Statement\":[{\"Action\":\"sts:AssumeRole\",\"Effect\":\"Allow\",\"Principal\":{\"RAM\":[\"acs:ram::{account_id}:root\"]}}],\"Version\":\"1\"}"
    }
}

# --- إعداد تسجيل الدخول ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, access_key, secret_key, token=None):
        self.id = id
        self.access_key = access_key
        self.secret_key = secret_key
        self.token = token

@login_manager.user_loader
def load_user(user_id):
    access_key = session.get('access_key')
    secret_key = session.get('secret_key')
    token = session.get('security_token') # ✅ استرجاع التوكين من الجلسة
    if user_id and access_key and secret_key:
        return User(id=user_id, access_key=access_key, secret_key=secret_key, token=token)
    return None

# --- دوال المساعدة ---

def get_ram_client():
    # ✅ تعديل مهم: إذا كان هناك توكين (STS) نستخدمه، وإلا نستخدم المفاتيح العادية
    if current_user.token:
        return AcsClient(current_user.access_key, current_user.secret_key, REGION_ID, security_token=current_user.token)
    return AcsClient(current_user.access_key, current_user.secret_key, REGION_ID)

def write_audit_log(message):
    try:
        user_type = "STS-User" if current_user.token else "Admin-User"
        with open("audit_log.log", "a", encoding="utf-8") as f:
            f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] - User: {current_user.id} ({user_type}) - Action: {message}\n")
    except:
        pass 

def get_audit_log_stats():
    stats = {'user_created': 0, 'user_updated': 0, 'user_deleted': 0, 'group_created': 0, 'group_deleted': 0, 'role_created': 0, 'role_updated': 0, 'role_deleted': 0, 'sts_generated': 0, 'logins': 0}
    if os.path.exists("audit_log.log"):
        try:
            with open("audit_log.log", "r", encoding="utf-8") as f:
                content = f.read()
                stats['logins'] = content.count("Login successful")
                stats['user_created'] = content.count("Created user")
                stats['user_deleted'] = content.count("Deleted user")
                stats['user_updated'] = content.count("Updated policies")
                stats['group_created'] = content.count("Created group")
                stats['group_deleted'] = content.count("Deleted group")
                stats['role_created'] = content.count("Created role")
                stats['role_deleted'] = content.count("Deleted role")
                stats['sts_generated'] = content.count("Generated temporary")
        except: pass
    return stats

def read_audit_log():
    if not os.path.exists("audit_log.log"): return []
    log_entries = []
    try:
        with open("audit_log.log", "r", encoding="utf-8") as f:
            for line in reversed(f.readlines()):
                parts = line.strip().split(' - ', 2)
                if len(parts) == 3:
                    log_entries.append({'timestamp': parts[0], 'user': parts[1].replace("User: ", ""), 'action': parts[2].replace("Action: ", "")})
    except: pass
    return log_entries

# ... (باقي دوال get_ram_users, get_groups, etc. لم تتغير ونبقيها كما هي) ...
# سأضع لك الدوال المساعدة الأساسية هنا لضمان عمل الكود
def get_user_policies_list(client, username):
    try:
        req = ListPoliciesForUserRequest.ListPoliciesForUserRequest(); req.set_accept_format('json'); req.set_UserName(username)
        resp = client.do_action_with_exception(req); return [p.get('PolicyName') for p in json.loads(resp).get('Policies', {}).get('Policy', [])]
    except: return []

def get_ram_users():
    try:
        client = get_ram_client(); req = ListUsersRequest.ListUsersRequest(); req.set_accept_format('json')
        resp = client.do_action_with_exception(req); data = json.loads(resp); users = []
        for u in data.get('Users', {}).get('User', []):
            pols = get_user_policies_list(client, u.get('UserName'))
            users.append({'UserName': u.get('UserName'), 'DisplayName': u.get('DisplayName'), 'CreateDate': u.get('CreateDate'), 'Comments': u.get('Comments'), 'Policies': ", ".join(pols) if pols else "None"})
        return users
    except Exception as e: flash(f"Error: {e}", "danger"); return []

def get_ram_groups():
    try:
        client = get_ram_client(); req = ListGroupsRequest.ListGroupsRequest(); req.set_accept_format('json')
        resp = client.do_action_with_exception(req); return json.loads(resp).get('Groups', {}).get('Group', [])
    except: return []

def get_ram_roles():
    try:
        client = get_ram_client(); req = ListRolesRequest.ListRolesRequest(); req.set_accept_format('json')
        resp = client.do_action_with_exception(req); return json.loads(resp).get('Roles', {}).get('Role', [])
    except: return []

def get_caller_identity():
    try:
        client = get_ram_client(); req = GetCallerIdentityRequest.GetCallerIdentityRequest(); req.set_accept_format('json')
        return json.loads(client.do_action_with_exception(req)).get('AccountId')
    except: return None

# --- المسارات (Routes) ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        try:
            # الخيار 1: تسجيل الدخول بملف (المفاتيح الدائمة)
            if 'key_file' in request.files and request.files['key_file'].filename != '':
                f = request.files.get('key_file')
                stream = io.StringIO(f.stream.read().decode("utf-8-sig"), newline=None)
                r = csv.reader(stream)
                next(r, None) 
                row = next(r)
                user = User(id=request.form.get('username'), access_key=row[0], secret_key=row[1])
                session['access_key'] = row[0]
                session['secret_key'] = row[1]
                session['security_token'] = None # تفريغ التوكين
                login_user(user)
                write_audit_log("Login successful (Permanent Keys)")
                return redirect(url_for('index'))
            
            # الخيار 2: تسجيل الدخول اليدوي (مفاتيح STS)
            elif request.form.get('ak_manual') and request.form.get('sk_manual'):
                ak = request.form.get('ak_manual')
                sk = request.form.get('sk_manual')
                token = request.form.get('token_manual') # قد يكون فارغاً أو ممتلئاً
                
                # استخدام ID مؤقت للاسم
                user_id = "STS_User" if token else "Manual_User"
                
                user = User(id=user_id, access_key=ak, secret_key=sk, token=token)
                session['access_key'] = ak
                session['secret_key'] = sk
                session['security_token'] = token # حفظ التوكين في الجلسة
                
                login_user(user)
                write_audit_log(f"Login successful ({'STS' if token else 'Manual'})")
                return redirect(url_for('index'))
                
            else:
                flash("الرجاء رفع ملف CSV أو إدخال المفاتيح يدوياً", "danger")

        except Exception as e:
            flash(str(e), "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index(): return render_template('index.html', stats=get_audit_log_stats())

@app.route('/users')
@login_required
def users(): return render_template('users.html', users=get_ram_users())

@app.route('/groups')
@login_required
def list_groups(): return render_template('groups.html', groups=get_ram_groups())

@app.route('/roles')
@login_required
def list_roles(): return render_template('roles.html', roles=get_ram_roles())

@app.route('/logs')
@login_required
def view_logs(): return render_template('logs.html', log_entries=read_audit_log())

@app.route('/sts', methods=['GET', 'POST'])
@login_required
def generate_sts_token():
    creds = None
    form = request.form
    if request.method == 'POST':
        try:
            client = get_ram_client()
            req = AssumeRoleRequest.AssumeRoleRequest()
            req.set_accept_format('json')
            req.set_RoleArn(form.get('role_arn'))
            req.set_RoleSessionName('session')
            req.set_DurationSeconds(int(form.get('duration'))*60)
            creds = json.loads(client.do_action_with_exception(req)).get('Credentials')
            write_audit_log(f"STS generated for {form.get('role_arn')}")
        except Exception as e:
            flash(str(e), "danger")
    return render_template('sts.html', roles=get_ram_roles(), credentials=creds, form_data=form)

@app.route('/create_user', methods=['GET', 'POST'])
@login_required
def create_user():
    if request.method == 'POST':
        try:
            client = get_ram_client()
            req = CreateUserRequest.CreateUserRequest(); req.set_accept_format('json')
            req.set_UserName(request.form['username']); req.set_DisplayName(request.form['display_name'])
            req.set_Comments(f"{request.form.get('phone')} | {request.form.get('national_id')}")
            client.do_action_with_exception(req)
            
            k_req = CreateAccessKeyRequest.CreateAccessKeyRequest(); k_req.set_accept_format('json')
            k_req.set_UserName(request.form['username'])
            k_resp = client.do_action_with_exception(k_req); k_data = json.loads(k_resp).get('AccessKey')
            new_ak = k_data.get('AccessKeyId'); new_sk = k_data.get('AccessKeySecret')

            for p in request.form.getlist('policy_names'):
                if p != "no_policy":
                    att = AttachPolicyToUserRequest.AttachPolicyToUserRequest(); att.set_accept_format('json')
                    att.set_PolicyType('System'); att.set_PolicyName(p); att.set_UserName(request.form['username'])
                    client.do_action_with_exception(att)
            grp = request.form.get('group_name')
            if grp and grp != "no_group":
                g = AddUserToGroupRequest.AddUserToGroupRequest(); g.set_UserName(request.form['username']); g.set_GroupName(grp)
                client.do_action_with_exception(g)
            
            write_audit_log(f"Created user {request.form['username']} with keys")
            flash(f"تم! انسخ المفاتيح الآن: ID: {new_ak} | Secret: {new_sk}", "success")
            return redirect(url_for('users'))
        except Exception as e: flash(str(e), "danger")
    return render_template('create_user.html', policies=AVAILABLE_POLICIES, groups=get_ram_groups())

@app.route('/delete_user/<username>', methods=['POST'])
@login_required
def delete_user(username):
    try:
        client = get_ram_client()
        for p in get_user_policies_list(client, username):
            d = DetachPolicyFromUserRequest.DetachPolicyFromUserRequest(); d.set_PolicyType('System'); d.set_PolicyName(p); d.set_UserName(username); client.do_action_with_exception(d)
        req = DeleteUserRequest.DeleteUserRequest(); req.set_UserName(username); client.do_action_with_exception(req)
        write_audit_log(f"Deleted {username}"); flash("تم الحذف", "success")
    except Exception as e: flash(str(e), "danger")
    return redirect(url_for('users'))

@app.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if request.method == 'POST':
        try:
            client = get_ram_client(); req = CreateGroupRequest.CreateGroupRequest(); req.set_accept_format('json')
            req.set_GroupName(request.form['group_name']); client.do_action_with_exception(req)
            policies_list = request.form.getlist('policy_names')
            if policies_list:
                for p in policies_list:
                    if p and p != "no_policy":
                        att = AttachPolicyToGroupRequest.AttachPolicyToGroupRequest(); att.set_accept_format('json')
                        att.set_PolicyType('System'); att.set_PolicyName(p); att.set_GroupName(request.form['group_name']); client.do_action_with_exception(att)
            write_audit_log(f"Created group {request.form['group_name']}"); flash("تم", "success"); return redirect(url_for('list_groups'))
        except Exception as e: flash(str(e), "danger")
    return render_template('create_group.html', policies=AVAILABLE_POLICIES)

@app.route('/delete_group/<group_name>', methods=['POST'])
@login_required
def delete_group(group_name):
    try:
        client = get_ram_client(); req = DeleteGroupRequest.DeleteGroupRequest(); req.set_GroupName(group_name)
        client.do_action_with_exception(req); write_audit_log(f"Deleted group {group_name}"); flash("تم", "success")
    except Exception as e: flash(str(e), "danger")
    return redirect(url_for('list_groups'))

@app.route('/create_role', methods=['GET', 'POST'])
@login_required
def create_role():
    if request.method == 'POST':
        try:
            t = TRUST_POLICY_TEMPLATES.get(request.form['trust_policy_key'])
            doc = t['policy_document'].replace("{account_id}", get_caller_identity() or "")
            req = CreateRoleRequest.CreateRoleRequest(); req.set_accept_format('json')
            req.set_RoleName(request.form['role_name']); req.set_AssumeRolePolicyDocument(doc)
            get_ram_client().do_action_with_exception(req)
            write_audit_log(f"Created role {request.form['role_name']}"); flash("تم", "success"); return redirect(url_for('list_roles'))
        except Exception as e: flash(str(e), "danger")
    return render_template('create_role.html', trust_policies=TRUST_POLICY_TEMPLATES)

@app.route('/delete_role/<role_name>', methods=['POST'])
@login_required
def delete_role(role_name):
    try:
        client = get_ram_client(); req = DeleteRoleRequest.DeleteRoleRequest(); req.set_RoleName(role_name)
        client.do_action_with_exception(req); write_audit_log(f"Deleted role {role_name}"); flash("تم", "success")
    except Exception as e: flash(str(e), "danger")
    return redirect(url_for('list_roles'))

@app.route('/edit_user/<username>', methods=['GET','POST'])
@login_required
def edit_user(username): return redirect(url_for('users'))

@app.route('/edit_role/<role_name>', methods=['GET','POST'])
@login_required
def edit_role(role_name): return redirect(url_for('list_roles'))
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True, reloader_type='stat')