from flask import Flask, request, jsonify
from flask_cors import CORS
import smtplib
import random
import string
import uuid
from datetime import datetime, timedelta
import psycopg2
import psycopg2.extras

app = Flask(__name__)
CORS(app)

# ===== CONFIG (ไม่ใช้ dotenv) =====
DB_CONFIG = {
    "dbname": "neondb",
    "user": "neondb_owner",
    "password": "npg_ziL1TrsZoaG2",
    "host": "ep-dark-water-a4qnqpyd.us-east-1.aws.neon.tech",
    "port": "5432",
    "sslmode": "require"
}

EMAIL_CONFIG = {
    "sender_email": "ditv9543@gmail.com",
    "sender_password": "uaee_gbkf_epqq_hlsm"
}

# ===== CONNECT DATABASE =====
conn = psycopg2.connect(**DB_CONFIG)
conn.autocommit = True

@app.route("/", methods=["GET"])
def home():
    return "hi api"

# ===== KEY SYSTEM =====

@app.route("/admin/create-key", methods=["GET"])
def create_key():
    key = request.args.get("key")
    uses = int(request.args.get("uses", 100))

    if not key:
        return jsonify({"status": "error", "message": "Key is required"}), 400

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO api_keys (key, uses)
            VALUES (%s, %s)
            ON CONFLICT (key) DO UPDATE SET uses = EXCLUDED.uses, updated_at = CURRENT_TIMESTAMP
            """,
            (key, uses)
        )
        return jsonify({"status": "success", "key": key, "uses": uses})

@app.route("/admin/status/<string:key>", methods=["GET"])
def key_status(key):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT uses FROM api_keys WHERE key = %s", (key,))
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "Key not found"}), 404
        return jsonify({"status": "success", "key": key, "uses_left": row["uses"]})

@app.route("/admin/delete-key/<string:key>", methods=["GET"])
def delete_key(key):
    with conn.cursor() as cur:
        cur.execute("DELETE FROM api_keys WHERE key = %s RETURNING key", (key,))
        result = cur.fetchone()
        if result:
            return jsonify({"status": "success", "message": f"Key {key} deleted"})
        return jsonify({"status": "error", "message": "Key not found"}), 404

# ===== OTP SYSTEM =====

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_email_otp(email, otp, reference_id):
    subject = "Your OTP Code"
    body = f"Your OTP code is: {otp}\nReference ID: {reference_id}\n(This OTP expires in 30 seconds.)"
    message = f"Subject: {subject}\n\n{body}"

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["sender_email"], EMAIL_CONFIG["sender_password"])
            server.sendmail(EMAIL_CONFIG["sender_email"], email, message)
        return True
    except Exception as e:
        print("Error sending email:", e)
        return False

@app.route("/send-otp/<string:email>/<string:key>", methods=["GET"])
def send_otp(email, key):
    if not email or not key:
        return jsonify({"status": "error", "message": "Email and API key are required"}), 400

    with conn.cursor() as cur:
        cur.execute("SELECT uses FROM api_keys WHERE key = %s", (key,))
        result = cur.fetchone()

        if not result:
            return jsonify({"status": "error", "message": "Invalid API key"}), 403

        uses_left = result[0]
        if uses_left < 2:
            return jsonify({"status": "error", "message": "Not enough key uses left"}), 403

        cur.execute(
            "UPDATE api_keys SET uses = uses - 2, updated_at = %s WHERE key = %s",
            (datetime.utcnow(), key)
        )

    otp = generate_otp()
    reference_id = str(uuid.uuid4())[:10]
    expires_at = datetime.utcnow() + timedelta(seconds=30)

    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO otp_store (reference_id, otp, expires_at) VALUES (%s, %s, %s)",
            (reference_id, otp, expires_at)
        )

    if send_email_otp(email, otp, reference_id):
        return jsonify({
            "status": "success",
            "reference_id": reference_id,
            "uses_left": uses_left - 2
        })
    else:
        return jsonify({"status": "error", "message": "Failed to send OTP"}), 500

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    reference_id = data.get("reference_id")
    user_otp = data.get("otp")

    if not reference_id or not user_otp:
        return jsonify({"status": "error", "message": "Missing reference_id or otp"}), 400

    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM otp_store WHERE reference_id = %s", (reference_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"status": "error", "message": "Invalid or expired reference ID"}), 400

        if datetime.utcnow() > row["expires_at"]:
            cur.execute("DELETE FROM otp_store WHERE reference_id = %s", (reference_id,))
            return jsonify({"status": "error", "message": "OTP expired"}), 403

        if row["otp"] == user_otp:
            cur.execute("DELETE FROM otp_store WHERE reference_id = %s", (reference_id,))
            return jsonify({"status": "success", "message": "OTP verified"})
        else:
            return jsonify({"status": "error", "message": "Incorrect OTP"}), 401

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
