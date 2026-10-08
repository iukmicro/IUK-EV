import os
import secrets
import hmac
import hashlib
import json
import mimetypes
import re
import time
from datetime import datetime
from decimal import Decimal, InvalidOperation
from math import isfinite
from pathlib import Path
from fastapi import FastAPI, Request, Form, File as FormFile, Depends, status, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.exc import IntegrityError
from sqlalchemy import func
from sqlalchemy.orm import Session

# Local application imports (using package relative/absolute imports)
try:
    from app.database import SessionLocal, engine, get_db, init_db
    from app.models import User, Vehicle, Rental, VehicleRequest, Transaction, BreakdownReport, RiderDocument, AccountStatusAudit, AdminNotification
    from app.auth import hash_password, verify_password
except ImportError:
    from database import SessionLocal, engine, get_db, init_db
    from models import User, Vehicle, Rental, VehicleRequest, Transaction, BreakdownReport, RiderDocument, AccountStatusAudit, AdminNotification
    from auth import hash_password, verify_password

# Create tables if not already present
init_db(engine)

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(title="Urban EV Fleet Rental Platform")

# Mount static folder
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Template configuration
templates = Jinja2Templates(directory="app/templates")
PRIVATE_DOCUMENT_DIR = BASE_DIR / "private_uploads" / "rider_documents"
MAX_DOCUMENT_SIZE = 100 * 1024 * 1024
DOCUMENT_FIELDS = {
    "driving_license": ("driving_license_path", "driving-license"),
    "aadhaar_card": ("aadhaar_card_path", "aadhaar-card"),
    "bank_passbook": ("bank_passbook_path", "bank-passbook"),
    "passport_photo": ("passport_photo_path", "passport-photo"),
}
def load_session_secret(secret_path: Path) -> bytes:
    configured_secret = os.environ.get("APP_SESSION_SECRET")
    if configured_secret:
        return configured_secret.encode("utf-8")

    secret_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with secret_path.open("xb") as secret_file:
            secret_file.write(secrets.token_bytes(32))
    except FileExistsError:
        pass

    secret = secret_path.read_bytes()
    if len(secret) != 32:
        raise RuntimeError(
            f"Session secret at {secret_path} must contain exactly 32 bytes."
        )
    return secret


SESSION_SECRET_BYTES = load_session_secret(BASE_DIR / ".session_secret")
AUTH_COOKIE_NAMES = {
    "admin": "admin_user_id",
    "rider": "rider_user_id",
}


def sign_user_id(user_id: int) -> str:
    user_id_value = str(user_id)
    signature = hmac.new(
        SESSION_SECRET_BYTES,
        user_id_value.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    return f"{user_id_value}.{signature}"


def get_current_user(request: Request, db: Session, role: str):
    user = get_signed_in_user(request, db, role)
    if (
        not user
        or user.role != role
        or (user.role == "rider" and user.password_reset_required)
        or (user.role == "rider" and user.account_status != "active")
    ):
        return None
    return user


def get_signed_in_user(request: Request, db: Session, role: str | None = None):
    if role is None:
        if request.url.path == "/admin" or request.url.path.startswith("/admin/"):
            role = "admin"
        elif request.url.path == "/rider" or request.url.path.startswith("/rider/"):
            role = "rider"
        else:
            return None

    cookie_value = request.cookies.get(AUTH_COOKIE_NAMES[role], "")
    if not cookie_value:
        cookie_value = request.cookies.get("user_id", "")
    user_id, separator, signature = cookie_value.partition(".")
    if not separator:
        return None
    expected_signature = hmac.new(
        SESSION_SECRET_BYTES,
        user_id.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return None
    try:
        return db.query(User).filter(User.id == int(user_id)).first()
    except (TypeError, ValueError):
        return None


async def inspect_document_upload(upload: UploadFile) -> tuple[str, int]:
    extension = Path(upload.filename or "").suffix.lower()
    size = upload.size

    if size is not None and size > MAX_DOCUMENT_SIZE:
        raise ValueError("Please upload each image or PDF within 100 MB.")
    if size == 0:
        raise ValueError("Each document must contain a file.")

    header = await upload.read(12)
    await upload.seek(0)
    if size is None:
        size = 0
        while chunk := await upload.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_DOCUMENT_SIZE:
                raise ValueError("Please upload each image or PDF within 100 MB.")
        await upload.seek(0)
        if size == 0:
            raise ValueError("Each document must contain a file.")

    is_allowed_file = (
        (extension in {".jpg", ".jpeg"} and header.startswith(b"\xff\xd8\xff"))
        or (extension == ".png" and header.startswith(b"\x89PNG\r\n\x1a\n"))
        or (
            extension == ".webp"
            and header[:4] == b"RIFF"
            and header[8:12] == b"WEBP"
        )
        or (extension == ".pdf" and header.startswith(b"%PDF-"))
    )
    if not is_allowed_file:
        raise ValueError("Use JPG, PNG, WEBP, or PDF files for all four documents.")
    return extension, size


async def save_document_upload(upload: UploadFile, destination: Path) -> None:
    written = 0
    try:
        with destination.open("xb") as output:
            while chunk := await upload.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_DOCUMENT_SIZE:
                    raise ValueError("Please upload each image or PDF within 100 MB.")
                output.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        await upload.seek(0)


def rider_dashboard_context(user: User, db: Session) -> dict:
    active_rental = db.query(Rental).filter(
        Rental.user_id == user.id,
        Rental.status == "active"
    ).first()
    active_breakdown = None
    if active_rental:
        active_breakdown = db.query(BreakdownReport).filter(
            BreakdownReport.rental_id == active_rental.id,
            BreakdownReport.status != "resolved"
        ).first()
    vehicle_request = db.query(VehicleRequest).filter(
        VehicleRequest.user_id == user.id,
        VehicleRequest.status.in_(("pending", "rejected"))
    ).order_by(VehicleRequest.requested_at.desc()).first()

    return {
        "user": user,
        "available_count": db.query(Vehicle).filter(Vehicle.is_available.is_(True)).count(),
        "active_rental": active_rental,
        "vehicle_request": vehicle_request,
        "active_breakdown": active_breakdown,
        "transactions": db.query(Transaction)
        .filter(Transaction.user_id == user.id)
        .order_by(Transaction.created_at.desc())
        .limit(10)
        .all(),
        "rider_documents": db.query(RiderDocument)
        .filter(RiderDocument.rider_id == user.id)
        .first(),
        "upload_error": None,
        "rental_notice": None,
    }


# --------------------------------------------------------------------------
# Public Page Routes
# --------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def home_page(request: Request):
    """Renders the main landing page."""
    return templates.TemplateResponse(request=request, name="home.html")


@app.get("/services", response_class=HTMLResponse)
def services_page(request: Request):
    """Renders the services template."""
    return templates.TemplateResponse(request=request, name="services.html")


@app.get("/fleet")
def fleet_info_page():
    """Redirects the legacy fleet URL to the homepage."""
    return RedirectResponse(
        url="/",
        status_code=status.HTTP_303_SEE_OTHER
    )


# --------------------------------------------------------------------------
# Authentication & Onboarding Routes
# --------------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Renders the standalone login page."""
    return templates.TemplateResponse(request=request, name="login.html")


@app.post("/login", response_class=HTMLResponse)
def handle_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Processes user sign-in and enforces onboarding approval constraints."""
    username = username.strip()
    user = db.query(User).filter(User.username == username).first()
    if not user:
        normalized_mobile = re.sub(r"[\s()-]", "", username)
        if re.fullmatch(r"\+?[1-9]\d{6,14}", normalized_mobile):
            user = db.query(User).filter(
                User.mobile_number == normalized_mobile
            ).first()
    if not user and username:
        matching_riders = db.query(User).filter(
            User.role == "rider",
            func.lower(User.full_name) == username.lower()
        ).limit(2).all()
        if len(matching_riders) == 1:
            user = matching_riders[0]

    is_valid_pw = False
    if user:
        stored_hash = getattr(user, "password_hash", None) or getattr(user, "hashed_password", None)
        if stored_hash:
            try:
                is_valid_pw = verify_password(password, stored_hash)
            except Exception:
                is_valid_pw = False

    if not user or not is_valid_pw:
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Invalid username or password."}, status_code=status.HTTP_401_UNAUTHORIZED)

    if user.role != "admin" and not user.is_approved:
        return templates.TemplateResponse(request=request, name="login.html", context={"error": "Your account is pending administrator approval. Please contact support."}, status_code=status.HTTP_403_FORBIDDEN)
    if user.role == "rider" and user.account_status != "active":
        account_status_label = {
            "on_hold": "on hold",
            "suspended": "suspended",
        }.get(user.account_status, "unavailable")
        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": f"Your account is {account_status_label}. Please contact the administrator."
            },
            status_code=status.HTTP_403_FORBIDDEN
        )

    redirect_url = (
        "/admin"
        if user.role == "admin"
        else "/rider/password-reset"
        if user.password_reset_required
        else "/rider"
    )
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key=AUTH_COOKIE_NAMES["admin" if user.role == "admin" else "rider"],
        value=sign_user_id(user.id),
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="user_id", path="/")
    for cookie_name in AUTH_COOKIE_NAMES.values():
        response.delete_cookie(key=cookie_name, path="/")
    return response


@app.get("/rider/password-reset", response_class=HTMLResponse)
def rider_password_reset_page(request: Request, db: Session = Depends(get_db)):
    user = get_signed_in_user(request, db, "rider")
    if (
        not user
        or user.role != "rider"
        or not user.password_reset_required
        or user.account_status != "active"
    ):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    return templates.TemplateResponse(request=request, name="password_reset.html")


@app.post("/rider/password-reset", response_class=HTMLResponse)
def reset_rider_password(
    request: Request,
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = get_signed_in_user(request, db, "rider")
    if (
        not user
        or user.role != "rider"
        or not user.password_reset_required
        or user.account_status != "active"
    ):
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    if len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="password_reset.html",
            context={"error": "Your password must be at least 8 characters long."},
            status_code=status.HTTP_400_BAD_REQUEST
        )
    if password != confirm_password:
        return templates.TemplateResponse(
            request=request,
            name="password_reset.html",
            context={"error": "The passwords do not match."},
            status_code=status.HTTP_400_BAD_REQUEST
        )

    user.password_hash = hash_password(password)
    user.password_reset_required = False
    db.commit()
    return RedirectResponse(url="/rider", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    """Renders user registration form."""
    return templates.TemplateResponse(request=request, name="register.html")


@app.post("/register", response_class=HTMLResponse)
def handle_register(
    request: Request,
    full_name: str = Form(...),
    mobile_number: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: Session = Depends(get_db)
):
    """Registers riders by mobile number and holds the account for admin approval."""
    full_name = full_name.strip()
    mobile_number = re.sub(r"[\s()-]", "", mobile_number)
    if not full_name or len(full_name) > 100:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Enter your name (up to 100 characters)."},
            status_code=status.HTTP_400_BAD_REQUEST
        )
    if not re.fullmatch(r"\+?[1-9]\d{6,14}", mobile_number):
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Enter a valid mobile number, including country code if needed."},
            status_code=status.HTTP_400_BAD_REQUEST
        )
    if len(password) < 8:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "Your password must be at least 8 characters long."},
            status_code=status.HTTP_400_BAD_REQUEST
        )
    if password != confirm_password:
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "The passwords do not match."},
            status_code=status.HTTP_400_BAD_REQUEST
        )

    existing_user = db.query(User).filter(User.username == mobile_number).first()
    if existing_user:
        return templates.TemplateResponse(request=request, name="register.html", context={"error": "An account with this mobile number already exists."}
        )

    new_user = User(
        username=mobile_number,
        full_name=full_name,
        mobile_number=mobile_number,
        password_hash=hash_password(password),
        role="rider",
        is_approved=False
    )
    db.add(new_user)
    try:
        db.flush()
        db.add(AdminNotification(
            category="rider_registration",
            reference_id=new_user.id,
            rider_id=new_user.id,
        ))
        db.commit()
    except IntegrityError:
        db.rollback()
        return templates.TemplateResponse(
            request=request,
            name="register.html",
            context={"error": "An account with this mobile number already exists."},
            status_code=status.HTTP_409_CONFLICT
        )

    return templates.TemplateResponse(request=request, name="login.html", context={"notice": "Registration submitted! Please wait for admin approval before signing in."}
    )


# --------------------------------------------------------------------------
# Protected Portals & Admin Approval Actions
# --------------------------------------------------------------------------

@app.get("/admin", response_class=HTMLResponse)
def admin_portal(request: Request, db: Session = Depends(get_db)):
    """Admin dashboard displaying fleet state and pending rider approvals."""
    user = get_current_user(request, db, "admin")
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    pending_riders = db.query(User).filter(User.role == "rider", User.is_approved == False).all()
    approved_riders = db.query(User).filter(User.role == "rider", User.is_approved == True).all()
    all_riders = db.query(User).filter(
        User.role == "rider"
    ).order_by(User.created_at.desc()).all()
    vehicles = db.query(Vehicle).all()
    rentals = db.query(Rental).all()
    pending_vehicle_requests = db.query(VehicleRequest).filter(
        VehicleRequest.status == "pending"
    ).order_by(VehicleRequest.requested_at.asc()).all()
    breakdown_reports = db.query(BreakdownReport).order_by(BreakdownReport.reported_at.desc()).limit(100).all()
    pending_document_sets = db.query(RiderDocument).filter(
        RiderDocument.status == "pending"
    ).order_by(RiderDocument.submitted_at.asc()).all()
    open_breakdown_count = db.query(BreakdownReport).filter(BreakdownReport.status != "resolved").count()
    resolved_breakdown_count = db.query(BreakdownReport).filter(BreakdownReport.status == "resolved").count()
    latest_notification_id = db.query(func.max(AdminNotification.id)).scalar() or 0
    breakdown_notice = request.query_params.get("breakdown_notice")
    document_notice = request.query_params.get("document_notice")
    rental_notice = request.query_params.get("rental_notice")
    rider_notice = request.query_params.get("rider_notice")
    rider_delete_notice = request.query_params.get("rider_delete_notice")
    account_notice = request.query_params.get("account_notice")
    status_notice = request.query_params.get("status_notice")
    password_notice = request.query_params.get("password_notice")
    plate_notice = request.query_params.get("plate_notice")
    rider_ids_with_history = {
        rider_id
        for (rider_id,) in db.query(Rental.user_id)
        .union(
            db.query(Transaction.user_id),
            db.query(BreakdownReport.rider_id),
            db.query(AccountStatusAudit.rider_id),
            db.query(AdminNotification.rider_id)
        )
        .all()
    }
    
    return templates.TemplateResponse(request=request, name="admin.html", context={
            "user": user,
            "pending_riders": pending_riders,
            "approved_riders": approved_riders,
            "all_riders": all_riders,
            "vehicles": vehicles,
            "rentals": rentals,
            "pending_vehicle_requests": pending_vehicle_requests,
            "breakdown_reports": breakdown_reports,
            "pending_document_sets": pending_document_sets,
            "open_breakdown_count": open_breakdown_count,
            "resolved_breakdown_count": resolved_breakdown_count,
            "latest_notification_id": latest_notification_id,
            "breakdown_notice": breakdown_notice,
            "document_notice": document_notice,
            "rental_notice": rental_notice,
            "rider_notice": rider_notice,
            "rider_delete_notice": rider_delete_notice,
            "account_notice": account_notice,
            "status_notice": status_notice,
            "password_notice": password_notice,
            "plate_notice": plate_notice,
            "rider_ids_with_history": rider_ids_with_history,
        }
    )


@app.get("/admin/events")
@app.get("/admin/breakdown/events")
def stream_admin_notifications(request: Request, after_id: int = 0):
    with SessionLocal() as db:
        user = get_current_user(request, db, "admin")
    if not user:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"detail": "Administrator authentication required."}
        )

    last_event_id = request.headers.get("last-event-id")
    if last_event_id and last_event_id.isdecimal():
        after_id = max(after_id, int(last_event_id))

    def event_stream():
        cursor = max(after_id, 0)
        last_heartbeat = time.monotonic()
        while True:
            with SessionLocal() as db:
                notifications = db.query(AdminNotification).filter(
                    AdminNotification.id > cursor
                ).order_by(AdminNotification.id.asc()).limit(50).all()
                events = [
                    {
                        "id": notification.id,
                        "category": notification.category,
                        "reference_id": notification.reference_id,
                        "rider_id": notification.rider_id,
                        "rider": notification.rider.full_name or notification.rider.username,
                        "username": notification.rider.username,
                        "mobile_number": notification.rider.mobile_number or notification.rider.username,
                        "wallet_balance": notification.rider.wallet_balance or 0.0,
                        "created_at": notification.created_at.isoformat() if notification.created_at else "",
                    }
                    for notification in notifications
                ]
                for event in events:
                    if event["category"] == "rider_documents":
                        document_set = db.query(RiderDocument).filter(
                            RiderDocument.id == event["reference_id"]
                        ).first()
                        if document_set:
                            event["created_at"] = document_set.submitted_at.isoformat() if document_set.submitted_at else event["created_at"]
                    elif event["category"] == "vehicle_request":
                        vehicle_request = db.query(VehicleRequest).filter(
                            VehicleRequest.id == event["reference_id"]
                        ).first()
                        if vehicle_request:
                            event["created_at"] = vehicle_request.requested_at.isoformat() if vehicle_request.requested_at else event["created_at"]
                    elif event["category"] == "breakdown":
                        report = db.query(BreakdownReport).filter(
                            BreakdownReport.id == event["reference_id"]
                        ).first()
                        if report:
                            event.update({
                                "created_at": report.reported_at.isoformat() if report.reported_at else event["created_at"],
                                "vehicle": report.vehicle.reg_number,
                                "description": report.description or "No details provided",
                                "latitude": report.latitude,
                                "longitude": report.longitude,
                                "location_accuracy": report.location_accuracy,
                            })

            for event in events:
                cursor = event["id"]
                yield f"id: {cursor}\ndata: {json.dumps(event)}\n\n"

            if not events and time.monotonic() - last_heartbeat >= 15:
                yield ": keepalive\n\n"
                last_heartbeat = time.monotonic()
            time.sleep(1)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.post("/admin/vehicle/plate")
def update_vehicle_plate(
    request: Request,
    vehicle_id: int = Form(...),
    reg_number: str = Form(...),
    db: Session = Depends(get_db)
):
    admin = get_current_user(request, db, "admin")
    if not admin:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    reg_number = reg_number.strip().upper()
    if not reg_number or len(reg_number) > 30:
        return RedirectResponse(
            url="/admin?plate_notice=invalid#fleet-inventory",
            status_code=status.HTTP_303_SEE_OTHER
        )

    vehicle = db.query(Vehicle).filter(Vehicle.id == vehicle_id).first()
    if not vehicle:
        return RedirectResponse(
            url="/admin?plate_notice=not-found#fleet-inventory",
            status_code=status.HTTP_303_SEE_OTHER
        )
    duplicate = db.query(Vehicle.id).filter(
        Vehicle.reg_number == reg_number,
        Vehicle.id != vehicle.id
    ).first()
    if duplicate:
        return RedirectResponse(
            url="/admin?plate_notice=duplicate#fleet-inventory",
            status_code=status.HTTP_303_SEE_OTHER
        )

    vehicle.reg_number = reg_number
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return RedirectResponse(
            url="/admin?plate_notice=duplicate#fleet-inventory",
            status_code=status.HTTP_303_SEE_OTHER
        )

    return RedirectResponse(
        url="/admin?plate_notice=updated#fleet-inventory",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/admin/rider/edit")
def edit_rider_account(
    request: Request,
    rider_id: int = Form(...),
    amount: str = Form(""),
    new_password: str = Form(""),
    confirm_new_password: str = Form(""),
    db: Session = Depends(get_db)
):
    admin = get_current_user(request, db, "admin")
    if not admin:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    has_amount = bool(amount.strip())
    password_change_requested = bool(new_password or confirm_new_password)
    if not has_amount and not password_change_requested:
        return RedirectResponse(
            url="/admin?account_notice=no-changes#all-riders",
            status_code=status.HTTP_303_SEE_OTHER
        )

    recharge_amount = None
    if has_amount:
        try:
            recharge_amount = Decimal(amount.strip())
        except InvalidOperation:
            recharge_amount = None
        if (
            recharge_amount is None
            or not recharge_amount.is_finite()
            or recharge_amount <= 0
            or recharge_amount > Decimal("1000000")
            or recharge_amount.as_tuple().exponent < -2
        ):
            return RedirectResponse(
                url="/admin?account_notice=invalid-amount#all-riders",
                status_code=status.HTTP_303_SEE_OTHER
            )

    if password_change_requested:
        if new_password != confirm_new_password:
            return RedirectResponse(
                url="/admin?account_notice=password-mismatch#all-riders",
                status_code=status.HTTP_303_SEE_OTHER
            )
        if len(new_password) < 8 or len(new_password) > 128:
            return RedirectResponse(
                url="/admin?account_notice=invalid-password#all-riders",
                status_code=status.HTTP_303_SEE_OTHER
            )

    rider = db.query(User).filter(
        User.id == rider_id,
        User.role == "rider"
    ).first()
    if not rider:
        return RedirectResponse(
            url="/admin?account_notice=rider-not-found#all-riders",
            status_code=status.HTTP_303_SEE_OTHER
        )

    if recharge_amount is not None:
        updated_balance = Decimal(str(rider.wallet_balance or 0.0)) + recharge_amount
        rider.wallet_balance = float(updated_balance)
        db.add(Transaction(
            user_id=rider.id,
            amount=float(recharge_amount),
            type="admin_wallet_credit",
            upi_ref=f"ADMIN-{admin.id}"
        ))
    if password_change_requested:
        rider.password_hash = hash_password(new_password)
        rider.password_reset_required = False

    db.commit()
    return RedirectResponse(
        url="/admin?account_notice=updated#all-riders",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/admin/rider/status")
def update_rider_status(
    request: Request,
    rider_id: int = Form(...),
    account_status: str = Form(...),
    db: Session = Depends(get_db)
):
    admin = get_current_user(request, db, "admin")
    if not admin:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    allowed_statuses = {"active", "on_hold", "suspended"}
    if account_status not in allowed_statuses:
        return RedirectResponse(
            url="/admin?status_notice=invalid-status#all-riders",
            status_code=status.HTTP_303_SEE_OTHER
        )

    rider = db.query(User).filter(
        User.id == rider_id,
        User.role == "rider"
    ).first()
    if not rider:
        return RedirectResponse(
            url="/admin?status_notice=rider-not-found#all-riders",
            status_code=status.HTTP_303_SEE_OTHER
        )

    previous_status = rider.account_status or "active"
    if previous_status == account_status:
        return RedirectResponse(
            url="/admin?status_notice=unchanged#all-riders",
            status_code=status.HTTP_303_SEE_OTHER
        )

    rider.account_status = account_status
    db.add(AccountStatusAudit(
        rider_id=rider.id,
        admin_id=admin.id,
        previous_status=previous_status,
        new_status=account_status,
    ))
    db.commit()
    return RedirectResponse(
        url="/admin?status_notice=updated#all-riders",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/admin/rider/password-reset")
def require_rider_password_reset(
    request: Request,
    rider_id: int = Form(...),
    db: Session = Depends(get_db)
):
    admin = get_current_user(request, db, "admin")
    if not admin:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    rider = db.query(User).filter(
        User.id == rider_id,
        User.role == "rider"
    ).first()
    if not rider:
        return RedirectResponse(
            url="/admin?password_notice=rider-not-found#all-riders",
            status_code=status.HTTP_303_SEE_OTHER
        )

    rider.password_reset_required = True
    db.commit()
    return RedirectResponse(
        url="/admin?password_notice=required#all-riders",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/admin/rider/approve")
def approve_rider(
    request: Request,
    rider_id: int = Form(...),
    db: Session = Depends(get_db)
):
    """Approve a pending rider."""
    user = get_current_user(request, db, "admin")
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    rider = db.query(User).filter(
        User.id == rider_id,
        User.role == "rider",
        User.is_approved.is_(False)
    ).first()
    if not rider:
        return RedirectResponse(
            url="/admin?rider_notice=not-found#rider-accounts",
            status_code=status.HTTP_303_SEE_OTHER
        )

    rider.is_approved = True
    db.commit()
    return RedirectResponse(
        url="/admin?rider_notice=approved#rider-accounts",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/admin/rider/reject")
def reject_rider(
    request: Request,
    rider_id: int = Form(...),
    db: Session = Depends(get_db)
):
    """Reject or remove a rider request."""
    user = get_current_user(request, db, "admin")
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    rider = db.query(User).filter(
        User.id == rider_id,
        User.role == "rider"
    ).first()
    if rider:
        has_history = any((
            db.query(Rental.id).filter(Rental.user_id == rider.id).first(),
            db.query(Transaction.id).filter(Transaction.user_id == rider.id).first(),
            db.query(BreakdownReport.id).filter(BreakdownReport.rider_id == rider.id).first(),
            db.query(AccountStatusAudit.id).filter(AccountStatusAudit.rider_id == rider.id).first(),
        ))
        if has_history:
            return RedirectResponse(
                url="/admin?rider_delete_notice=has-history#all-riders",
                status_code=status.HTTP_303_SEE_OTHER
            )
        document_set = db.query(RiderDocument).filter(
            RiderDocument.rider_id == rider.id
        ).first()
        stored_paths = [
            getattr(document_set, field_name)
            for field_name, _ in DOCUMENT_FIELDS.values()
        ] if document_set else []
        if document_set:
            db.delete(document_set)
        db.query(VehicleRequest).filter(
            VehicleRequest.user_id == rider.id
        ).delete(synchronize_session=False)
        db.delete(rider)
        db.commit()
        for stored_name in stored_paths:
            if Path(stored_name).name == stored_name:
                (PRIVATE_DOCUMENT_DIR / stored_name).unlink(missing_ok=True)
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/rider/delete")
def delete_rider(
    request: Request,
    rider_id: int = Form(...),
    db: Session = Depends(get_db)
):
    """Delete a rider account only when it has no rental, payment, or breakdown history."""
    admin = get_current_user(request, db, "admin")
    if not admin:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    rider = db.query(User).filter(
        User.id == rider_id,
        User.role == "rider"
    ).first()
    if not rider:
        return RedirectResponse(
            url="/admin?rider_delete_notice=not-found#all-riders",
            status_code=status.HTTP_303_SEE_OTHER
        )

    has_history = any((
        db.query(Rental.id).filter(Rental.user_id == rider.id).first(),
        db.query(Transaction.id).filter(Transaction.user_id == rider.id).first(),
        db.query(BreakdownReport.id).filter(BreakdownReport.rider_id == rider.id).first(),
        db.query(AccountStatusAudit.id).filter(AccountStatusAudit.rider_id == rider.id).first(),
    ))
    if has_history:
        return RedirectResponse(
            url="/admin?rider_delete_notice=has-history#all-riders",
            status_code=status.HTTP_303_SEE_OTHER
        )

    document_set = db.query(RiderDocument).filter(
        RiderDocument.rider_id == rider.id
    ).first()
    stored_paths = [
        getattr(document_set, field_name)
        for field_name, _ in DOCUMENT_FIELDS.values()
    ] if document_set else []
    if document_set:
        db.delete(document_set)
    db.query(VehicleRequest).filter(
        VehicleRequest.user_id == rider.id
    ).delete(synchronize_session=False)
    db.delete(rider)
    db.commit()

    for stored_name in stored_paths:
        if Path(stored_name).name == stored_name:
            (PRIVATE_DOCUMENT_DIR / stored_name).unlink(missing_ok=True)

    return RedirectResponse(
        url="/admin?rider_delete_notice=deleted#all-riders",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.get("/rider", response_class=HTMLResponse)
def rider_portal(request: Request, db: Session = Depends(get_db)):
    """Rider dashboard displaying available fleet for rental."""
    user = get_current_user(request, db, "rider")
    if not user or not user.is_approved:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    context = rider_dashboard_context(user, db)
    context["upload_notice"] = request.query_params.get("upload_notice")
    context["rental_notice"] = request.query_params.get("rental_notice")
    return templates.TemplateResponse(
        request=request,
        name="rider.html",
        context=context
    )


@app.post("/rider/documents")
async def upload_rider_documents(
    request: Request,
    driving_license: UploadFile = FormFile(...),
    aadhaar_card: UploadFile = FormFile(...),
    bank_passbook: UploadFile = FormFile(...),
    passport_photo: UploadFile = FormFile(...),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db, "rider")
    if not user or not user.is_approved:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    existing_set = db.query(RiderDocument).filter(
        RiderDocument.rider_id == user.id
    ).first()
    if existing_set and existing_set.status != "rejected":
        return RedirectResponse(url="/rider#documents", status_code=status.HTTP_303_SEE_OTHER)

    uploads = {
        "driving_license": driving_license,
        "aadhaar_card": aadhaar_card,
        "bank_passbook": bank_passbook,
        "passport_photo": passport_photo,
    }
    try:
        file_metadata = {
            key: await inspect_document_upload(upload)
            for key, upload in uploads.items()
        }
    except ValueError as error:
        context = rider_dashboard_context(user, db)
        context["upload_error"] = str(error)
        context["upload_notice"] = None
        return templates.TemplateResponse(
            request=request,
            name="rider.html",
            context=context,
            status_code=status.HTTP_400_BAD_REQUEST
        )

    PRIVATE_DOCUMENT_DIR.mkdir(parents=True, exist_ok=True)
    new_paths = {}
    try:
        for key, upload in uploads.items():
            extension, _ = file_metadata[key]
            stored_name = f"{secrets.token_hex(24)}{extension}"
            destination = PRIVATE_DOCUMENT_DIR / stored_name
            await save_document_upload(upload, destination)
            new_paths[key] = stored_name

        if existing_set:
            old_paths = [
                getattr(existing_set, field_name)
                for field_name, _ in DOCUMENT_FIELDS.values()
            ]
            for key, (field_name, _) in DOCUMENT_FIELDS.items():
                setattr(existing_set, field_name, new_paths[key])
            existing_set.status = "pending"
            existing_set.submitted_at = datetime.utcnow()
            existing_set.reviewed_at = None
        else:
            old_paths = []
            existing_set = RiderDocument(
                rider_id=user.id,
                driving_license_path=new_paths["driving_license"],
                aadhaar_card_path=new_paths["aadhaar_card"],
                bank_passbook_path=new_paths["bank_passbook"],
                passport_photo_path=new_paths["passport_photo"],
                status="pending",
            )
            db.add(existing_set)
        db.flush()
        db.add(AdminNotification(
            category="rider_documents",
            reference_id=existing_set.id,
            rider_id=user.id,
        ))
        db.commit()
    except Exception:
        db.rollback()
        for stored_name in new_paths.values():
            (PRIVATE_DOCUMENT_DIR / stored_name).unlink(missing_ok=True)
        raise

    for stored_name in old_paths:
        (PRIVATE_DOCUMENT_DIR / stored_name).unlink(missing_ok=True)
    return RedirectResponse(
        url="/rider?upload_notice=submitted#documents",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.get("/admin/rider-documents/{rider_id}/{document_type}")
def download_rider_document(
    request: Request,
    rider_id: int,
    document_type: str,
    download: bool = False,
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db, "admin")
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    document_set = db.query(RiderDocument).filter(
        RiderDocument.rider_id == rider_id
    ).first()
    if not document_set or document_type not in DOCUMENT_FIELDS:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found.")

    field_name, download_name = DOCUMENT_FIELDS[document_type]
    stored_name = getattr(document_set, field_name)
    if Path(stored_name).name != stored_name:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found.")
    document_path = PRIVATE_DOCUMENT_DIR / stored_name
    if not document_path.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document file is unavailable.")

    extension = document_path.suffix.lower()
    return FileResponse(
        path=document_path,
        media_type=mimetypes.guess_type(document_path.name)[0] or "application/octet-stream",
        filename=f"{download_name}{extension}",
        content_disposition_type="attachment" if download else "inline",
        headers={"Cache-Control": "no-store"},
    )


@app.post("/admin/rider-documents/{rider_id}/approve")
def approve_rider_documents(
    request: Request,
    rider_id: int,
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db, "admin")
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    document_set = db.query(RiderDocument).filter(
        RiderDocument.rider_id == rider_id,
        RiderDocument.status == "pending"
    ).first()
    if not document_set:
        return RedirectResponse(
            url="/admin?document_notice=already-reviewed#rider-documents",
            status_code=status.HTTP_303_SEE_OTHER
        )

    if any(
        not (PRIVATE_DOCUMENT_DIR / getattr(document_set, field_name)).is_file()
        for field_name, _ in DOCUMENT_FIELDS.values()
    ):
        return RedirectResponse(
            url="/admin?document_notice=missing-files#rider-documents",
            status_code=status.HTTP_303_SEE_OTHER
        )

    document_set.status = "approved"
    document_set.reviewed_at = datetime.utcnow()
    db.commit()
    return RedirectResponse(
        url="/admin?document_notice=approved#rider-documents",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/admin/rider-documents/{rider_id}/reject")
def reject_rider_documents(
    request: Request,
    rider_id: int,
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db, "admin")
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    document_set = db.query(RiderDocument).filter(
        RiderDocument.rider_id == rider_id,
        RiderDocument.status == "pending"
    ).first()
    if not document_set:
        return RedirectResponse(
            url="/admin?document_notice=already-reviewed#rider-documents",
            status_code=status.HTTP_303_SEE_OTHER
        )

    document_set.status = "rejected"
    document_set.reviewed_at = datetime.utcnow()
    db.commit()
    return RedirectResponse(
        url="/admin?document_notice=rejected#rider-documents",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/rider/vehicle/unlock")
def request_vehicle(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db, "rider")
    if not user or not user.is_approved:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    document_set = db.query(RiderDocument).filter(
        RiderDocument.rider_id == user.id,
        RiderDocument.status == "approved"
    ).first()
    if not document_set:
        return RedirectResponse(
            url="/rider?rental_notice=documents-required#documents",
            status_code=status.HTTP_303_SEE_OTHER
        )

    active_rental = db.query(Rental).filter(
        Rental.user_id == user.id,
        Rental.status == "active"
    ).first()
    if active_rental:
        return RedirectResponse(url="/rider", status_code=status.HTTP_303_SEE_OTHER)
    pending_request = db.query(VehicleRequest).filter(
        VehicleRequest.user_id == user.id,
        VehicleRequest.status == "pending"
    ).first()
    if pending_request:
        return RedirectResponse(url="/rider", status_code=status.HTTP_303_SEE_OTHER)
    if (user.wallet_balance or 0.0) < 100.0:
        return RedirectResponse(
            url="/rider?rental_notice=insufficient-balance",
            status_code=status.HTTP_303_SEE_OTHER
        )

    available_vehicle = db.query(Vehicle).filter(
        Vehicle.is_available.is_(True)
    ).first()
    if not available_vehicle:
        return RedirectResponse(
            url="/rider?rental_notice=no-vehicle",
            status_code=status.HTTP_303_SEE_OTHER
        )

    vehicle_request = VehicleRequest(user_id=user.id, status="pending")
    db.add(vehicle_request)
    db.flush()
    db.add(AdminNotification(
        category="vehicle_request",
        reference_id=vehicle_request.id,
        rider_id=user.id,
    ))
    db.commit()
    return RedirectResponse(
        url="/rider?rental_notice=request-submitted",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/admin/vehicle-request/approve")
def approve_vehicle_request(
    request: Request,
    request_id: int = Form(...),
    db: Session = Depends(get_db)
):
    admin = get_current_user(request, db, "admin")
    if not admin:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    vehicle_request = db.query(VehicleRequest).filter(
        VehicleRequest.id == request_id,
        VehicleRequest.status == "pending"
    ).first()
    if not vehicle_request:
        return RedirectResponse(
            url="/admin?rental_notice=already-reviewed#vehicle-requests",
            status_code=status.HTTP_303_SEE_OTHER
        )

    rider = vehicle_request.user
    documents = db.query(RiderDocument).filter(
        RiderDocument.rider_id == rider.id,
        RiderDocument.status == "approved"
    ).first()
    active_rental = db.query(Rental).filter(
        Rental.user_id == rider.id,
        Rental.status == "active"
    ).first()
    if (
        not rider.is_approved
        or rider.account_status != "active"
        or not documents
        or active_rental
    ):
        return RedirectResponse(
            url="/admin?rental_notice=rider-not-eligible#vehicle-requests",
            status_code=status.HTTP_303_SEE_OTHER
        )
    if (rider.wallet_balance or 0.0) < 100.0:
        return RedirectResponse(
            url="/admin?rental_notice=insufficient-balance#vehicle-requests",
            status_code=status.HTTP_303_SEE_OTHER
        )

    vehicle = db.query(Vehicle).filter(
        Vehicle.is_available.is_(True)
    ).order_by(Vehicle.id.asc()).first()
    if not vehicle:
        return RedirectResponse(
            url="/admin?rental_notice=no-vehicle#vehicle-requests",
            status_code=status.HTTP_303_SEE_OTHER
        )

    vehicle.is_available = False
    rider.wallet_balance = (rider.wallet_balance or 0.0) - 100.0
    vehicle_request.status = "approved"
    vehicle_request.reviewed_at = datetime.utcnow()
    db.add(Rental(user_id=rider.id, vehicle_id=vehicle.id, cost=100.0, status="active"))
    db.add(Transaction(user_id=rider.id, amount=-100.0, type="rental_fee"))
    db.commit()
    return RedirectResponse(
        url="/admin?rental_notice=approved#vehicle-requests",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/admin/vehicle-request/reject")
def reject_vehicle_request(
    request: Request,
    request_id: int = Form(...),
    db: Session = Depends(get_db)
):
    admin = get_current_user(request, db, "admin")
    if not admin:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    vehicle_request = db.query(VehicleRequest).filter(
        VehicleRequest.id == request_id,
        VehicleRequest.status == "pending"
    ).first()
    if not vehicle_request:
        return RedirectResponse(
            url="/admin?rental_notice=already-reviewed#vehicle-requests",
            status_code=status.HTTP_303_SEE_OTHER
        )

    vehicle_request.status = "rejected"
    vehicle_request.reviewed_at = datetime.utcnow()
    db.commit()
    return RedirectResponse(
        url="/admin?rental_notice=rejected#vehicle-requests",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/rider/vehicle/return")
def return_vehicle(request: Request, db: Session = Depends(get_db)):
    user = get_current_user(request, db, "rider")
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    rental = db.query(Rental).filter(
        Rental.user_id == user.id,
        Rental.status == "active"
    ).first()
    if not rental:
        return RedirectResponse(
            url="/rider?rental_notice=no-active-rental",
            status_code=status.HTTP_303_SEE_OTHER
        )

    rental.end_time = datetime.utcnow()
    rental.status = "completed"
    unresolved_breakdown = db.query(BreakdownReport.id).filter(
        BreakdownReport.vehicle_id == rental.vehicle_id,
        BreakdownReport.status != "resolved"
    ).first()
    if rental.vehicle and not unresolved_breakdown:
        rental.vehicle.is_available = True
    db.commit()

    return RedirectResponse(
        url="/rider?rental_notice=returned",
        status_code=status.HTTP_303_SEE_OTHER
    )


@app.post("/rider/breakdown")
def report_vehicle_breakdown(
    request: Request,
    description: str = Form(""),
    latitude: float = Form(...),
    longitude: float = Form(...),
    location_accuracy: float = Form(...),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db, "rider")
    if not user or not user.is_approved:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    rental = db.query(Rental).filter(Rental.user_id == user.id, Rental.status == "active").first()
    if not rental:
        return RedirectResponse(url="/rider", status_code=status.HTTP_303_SEE_OTHER)

    if (
        not isfinite(latitude)
        or not isfinite(longitude)
        or not isfinite(location_accuracy)
        or not -90 <= latitude <= 90
        or not -180 <= longitude <= 180
        or location_accuracy < 0
    ):
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Capture a valid location before reporting a breakdown.")

    existing_report = db.query(BreakdownReport).filter(
        BreakdownReport.rental_id == rental.id,
        BreakdownReport.status != "resolved"
    ).first()
    if not existing_report:
        report = BreakdownReport(
            rider_id=user.id,
            rental_id=rental.id,
            vehicle_id=rental.vehicle_id,
            description=description.strip()[:500],
            latitude=latitude,
            longitude=longitude,
            location_accuracy=location_accuracy
        )
        db.add(report)
        db.flush()
        db.add(AdminNotification(
            category="breakdown",
            reference_id=report.id,
            rider_id=user.id,
        ))
        db.commit()

    return RedirectResponse(url="/rider#breakdown", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/breakdown/approve")
def approve_breakdown_replacement(
    request: Request,
    report_id: int = Form(...),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db, "admin")
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    report = db.query(BreakdownReport).filter(
        BreakdownReport.id == report_id,
        BreakdownReport.status == "open"
    ).first()
    if not report:
        return RedirectResponse(url="/admin?breakdown_notice=already-processed#breakdowns", status_code=status.HTTP_303_SEE_OTHER)

    rental = db.query(Rental).filter(
        Rental.id == report.rental_id,
        Rental.user_id == report.rider_id,
        Rental.status == "active",
        Rental.vehicle_id == report.vehicle_id
    ).first()
    if not rental:
        return RedirectResponse(url="/admin?breakdown_notice=inactive-rental#breakdowns", status_code=status.HTTP_303_SEE_OTHER)

    replacement = db.query(Vehicle).filter(
        Vehicle.is_available.is_(True),
        Vehicle.id > report.vehicle_id
    ).order_by(Vehicle.id.asc()).first()
    if not replacement:
        replacement = db.query(Vehicle).filter(
            Vehicle.is_available.is_(True),
            Vehicle.id < report.vehicle_id
        ).order_by(Vehicle.id.asc()).first()
    if not replacement:
        return RedirectResponse(url="/admin?breakdown_notice=no-replacement#breakdowns", status_code=status.HTTP_303_SEE_OTHER)

    report.vehicle.is_available = False
    replacement.is_available = False
    rental.vehicle_id = replacement.id
    report.replacement_vehicle_id = replacement.id
    report.status = "replacement_assigned"
    report.approved_at = datetime.utcnow()
    db.commit()

    return RedirectResponse(url="/admin#breakdowns", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/admin/breakdown/resolve")
def resolve_breakdown_report(
    request: Request,
    report_id: int = Form(...),
    db: Session = Depends(get_db)
):
    user = get_current_user(request, db, "admin")
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)

    report = db.query(BreakdownReport).filter(
        BreakdownReport.id == report_id,
        BreakdownReport.status == "replacement_assigned"
    ).first()
    if report:
        report.status = "resolved"
        report.resolved_at = datetime.utcnow()
        has_active_rental = db.query(Rental.id).filter(
            Rental.vehicle_id == report.vehicle_id,
            Rental.status == "active"
        ).first()
        has_other_open_report = db.query(BreakdownReport.id).filter(
            BreakdownReport.vehicle_id == report.vehicle_id,
            BreakdownReport.id != report.id,
            BreakdownReport.status != "resolved"
        ).first()
        if not has_active_rental and not has_other_open_report:
            report.vehicle.is_available = True
        db.commit()

    return RedirectResponse(url="/admin#breakdowns", status_code=status.HTTP_303_SEE_OTHER)


# --------------------------------------------------------------------------
# Legal Pages
# --------------------------------------------------------------------------

@app.get("/privacy", response_class=HTMLResponse)
def privacy_page(request: Request):
    return templates.TemplateResponse(request=request, name="privacy.html")


@app.get("/terms", response_class=HTMLResponse)
def terms_page(request: Request):
    return templates.TemplateResponse(request=request, name="terms.html")
