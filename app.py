from flask import Flask, request, jsonify
from twilio.rest import Client
import os, json
from datetime import datetime
from flask_cors import CORS

# --------------------------
# FIREBASE
# --------------------------
import firebase_admin
from firebase_admin import credentials, firestore

# --------------------------
# INIT
# --------------------------
app = Flask(__name__)
CORS(app)

# --------------------------
# LOAD FIREBASE FROM ENV ONLY
# --------------------------
firebase_env_key = os.getenv("FIREBASE_KEY")

if not firebase_env_key:
    raise Exception("FIREBASE_KEY environment variable not found!")

firebase_key_dict = json.loads(firebase_env_key)
cred = credentials.Certificate(firebase_key_dict)

firebase_admin.initialize_app(cred)
db = firestore.client()

# --------------------------
# TWILIO CREDS
# --------------------------
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN  = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_VERIFY_SID  = os.getenv("TWILIO_VERIFY_SID")

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


# ============================================================
# REGISTER – SEND OTP
# ============================================================
@app.route('/register', methods=['POST'])
def start_registration():
    data = request.json
    phone = data.get("phone")
    name = data.get("name")

    if not phone or not name:
        return jsonify({"error": "Name and phone required"}), 400

    if db.collection("users").document(phone).get().exists:
        return jsonify({"message": "User already registered"}), 400

    verification = twilio_client.verify.services(TWILIO_VERIFY_SID).verifications.create(
        to=phone,
        channel="sms"
    )

    db.collection("registration_pending").document(phone).set({
        "name": name,
        "mobile": phone,
        "requestedAt": datetime.utcnow().isoformat()
    })

    return jsonify({"message": "OTP sent", "status": verification.status})


# ============================================================
# REGISTER – VERIFY OTP
# ============================================================
@app.route('/register/verify-otp', methods=['POST'])
def verify_registration_otp():
    data = request.json
    phone = data.get("phone")
    otp = data.get("otp")

    if not phone or not otp:
        return jsonify({"error": "Phone and OTP required"}), 400

    check = twilio_client.verify.services(TWILIO_VERIFY_SID).verification_checks.create(
        to=phone,
        code=otp
    )

    if check.status != "approved":
        return jsonify({"message": "Invalid OTP"}), 400

    pending = db.collection("registration_pending").document(phone).get().to_dict()
    if not pending:
        return jsonify({"error": "No registration pending"}), 400

    db.collection("users").document(phone).set({
        "name": pending["name"],
        "mobile": phone,
        "createdAt": datetime.utcnow().isoformat()
    })

    db.collection("registration_pending").document(phone).delete()

    return jsonify({
        "message": "Registration successful",
        "name": pending["name"],
        "phone": phone
    })


# ============================================================
# LOGIN – SEND OTP
# ============================================================
@app.route('/login', methods=['POST'])
def start_login():
    data = request.json
    phone = data.get("phone")

    if not phone:
        return jsonify({"error": "Phone required"}), 400

    if not db.collection("users").document(phone).get().exists:
        return jsonify({"message": "User not registered"}), 400

    verification = twilio_client.verify.services(TWILIO_VERIFY_SID).verifications.create(
        to=phone,
        channel="sms"
    )

    return jsonify({"message": "OTP sent", "status": verification.status})


# ============================================================
# LOGIN – VERIFY OTP
# ============================================================
@app.route('/login/verify-otp', methods=['POST'])
def verify_login_otp():
    data = request.json
    phone = data.get("phone")
    otp = data.get("otp")

    if not phone or not otp:
        return jsonify({"error": "Phone and OTP required"}), 400

    check = twilio_client.verify.services(TWILIO_VERIFY_SID).verification_checks.create(
        to=phone,
        code=otp
    )

    if check.status != "approved":
        return jsonify({"message": "Invalid OTP"}), 400

    user = db.collection("users").document(phone).get().to_dict()
    certs_stream = db.collection("users").document(phone).collection("certificates").stream()

    certificates = []
    for c in certs_stream:
        d = c.to_dict()
        d["id"] = c.id
        certificates.append(d)

    return jsonify({
        "message": "Login successful",
        "name": user["name"],
        "phone": phone,
        "documents": certificates
    })


# ============================================================
# ADD CERTIFICATE
# ============================================================
@app.route("/certificate/add", methods=["POST"])
def add_certificate():
    phone = request.headers.get("X-User-Phone")
    if not phone:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json

    db.collection("users").document(phone).collection("certificates").document().set({
        "certificate_type": data["certificate_type"],
        "certificate_name": data["certificate_name"],
        "holder_name": data["holder_name"],
        "identifier_number": data.get("identifier_number"),
        "ipfs_url": data["ipfs_url"],
        "source": "user_upload",
        "uploaded_at": datetime.utcnow().isoformat()
    })

    return jsonify({"message": "Certificate added"})


# ============================================================
# GET CERTIFICATES
# ============================================================
@app.route("/certificate/get/<mobile>", methods=["GET"])
def get_certificates(mobile):

    if not db.collection("users").document(mobile).get().exists:
        return jsonify({"error": "User not found"}), 404

    certs_stream = db.collection("users").document(mobile).collection("certificates").stream()

    docs = []
    for c in certs_stream:
        d = c.to_dict()
        d["id"] = c.id
        docs.append(d)

    return jsonify({
        "mobile": mobile,
        "certificates": docs
    })


from urllib.parse import unquote

# ============================================================
# GET SINGLE DOCUMENT (TYPE + IDENTIFIER VALIDATION)
# ============================================================
@app.route("/document/<mobile>/<cert_type>/<identifier>", methods=["GET"])
def get_single_document(mobile, cert_type, identifier):
    try:
        # ⭐ Decode URL-encoded values (important!)
        mobile = unquote(mobile)
        cert_type = unquote(cert_type)
        identifier = unquote(identifier)

        print("📥 Received Mobile:", mobile)
        print("📥 Received Certificate Type:", cert_type)
        print("📥 Received Identifier:", identifier)

        user_ref = db.collection("users").document(mobile)

        if not user_ref.get().exists:
            return jsonify({"error": "User not found"}), 404

        certs = user_ref.collection("certificates").stream()

        # Normalize inputs
        req_type = str(cert_type or "").strip().lower()
        # Remove only spaces inside number (ex: "1234 5678" → "12345678")
        req_identifier = str(identifier or "").replace(" ", "").strip()

        print("🔍 Checking for Type:", req_type)
        print("🔍 Checking for Identifier:", req_identifier)

        for cert in certs:
            data = cert.to_dict()

            db_type = str(data.get("certificate_type") or "").strip().lower()
            db_identifier = str(data.get("identifier_number") or "").replace(" ", "").strip()

            print("➡️ DB TYPE:", db_type, "| DB IDENT:", db_identifier)

            if db_type == req_type and db_identifier == req_identifier:
                return jsonify({
                    "status": "success",
                    "document": data
                }), 200

        return jsonify({
            "error": "Document not found for this certificate type"
        }), 404

    except Exception as e:
        print("❌ ERROR:", e)
        return jsonify({"error": "Server error"}), 500


# ============================================================
# GET USER BASIC DETAILS BY MOBILE (NO CERTIFICATES)
# ============================================================
@app.route("/user/<mobile>", methods=["GET"])
def get_user_details(mobile):
    try:
        user_ref = db.collection("users").document(mobile)
        user_doc = user_ref.get()

        if not user_doc.exists:
            return jsonify({"error": "User not found"}), 404

        user_data = user_doc.to_dict()

        return jsonify({
            "status": "success",
            "user": {
                "name": user_data.get("name"),
                "mobile": user_data.get("mobile"),
                "dob": user_data.get("dob") or user_data.get("DOB"),
                "gender": user_data.get("gender") or user_data.get("Gender"),
                "createdAt": user_data.get("createdAt") or user_data.get("CreatedAt")
            }
        }), 200


    except Exception as e:
        print("❌ ERROR:", e)
        return jsonify({"error": "Server error"}), 500

# ============================================================
# RUN LOCALLY
# ============================================================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
