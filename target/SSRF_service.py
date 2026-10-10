from flask import Flask, request, jsonify

app = Flask(__name__)
IMPORTANT_TOKEN='123456'
SECRET_TOKEN = "FLAG{IMPORTANT_TOKEN}"

# Список пользователей
USERS = ["admin", "user", "polina", "nastya", "gao", "marina", "alina"]

@app.route("/")
def home():
    return "Admin Panel. Use /admin for management."

@app.route("/admin")
def admin():
    return f"""
    <h1>Admin Panel</h1>
    <p>Secret token: {SECRET_TOKEN}</p>
    <ul>
        {''.join(f'<li>{u} <a href="/admin/delete?username={u}">delete</a></li>\n' for u in USERS)}
    </ul>
    """

@app.route("/admin/delete")
def delete():
    username = request.args.get("username", "")
    if username in USERS:
        USERS.remove(username)
        return f"Deleted: {username}"
    return f"User not found: {username}"

@app.route("/metadata")
def metadata():
    """Имитация облачных метаданных — обычно на 169.254.169.254."""
    return jsonify({
        "instance-id": "i-1234567890abcdef0",
        "iam": {
            "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
            "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "Token": "FQoGZXIvYXdzEBYaD..."
        }
    })

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=False)