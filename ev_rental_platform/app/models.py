from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    mobile_number = Column(String(20), nullable=True)
    role = Column(String(20), default="rider")  # 'admin' or 'rider'
    is_approved = Column(Boolean, default=False)  # Admin approval required for riders
    password_reset_required = Column(Boolean, default=False, nullable=False)
    account_status = Column(String(20), default="active", nullable=False, index=True)
    wallet_balance = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    rentals = relationship("Rental", back_populates="user")
    vehicle_requests = relationship("VehicleRequest", back_populates="user")
    transactions = relationship("Transaction", back_populates="user")
    rider_documents = relationship("RiderDocument", back_populates="rider", uselist=False)
    status_audits = relationship(
        "AccountStatusAudit",
        foreign_keys="AccountStatusAudit.rider_id",
        order_by="AccountStatusAudit.created_at.desc()",
        back_populates="rider",
    )


class AccountStatusAudit(Base):
    __tablename__ = "account_status_audits"

    id = Column(Integer, primary_key=True, index=True)
    rider_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    previous_status = Column(String(20), nullable=False)
    new_status = Column(String(20), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    rider = relationship("User", foreign_keys=[rider_id], back_populates="status_audits")
    admin = relationship("User", foreign_keys=[admin_id])


class AdminNotification(Base):
    __tablename__ = "admin_notifications"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String(30), nullable=False, index=True)
    reference_id = Column(Integer, nullable=False)
    rider_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    rider = relationship("User")


class RiderDocument(Base):
    __tablename__ = "rider_documents"

    id = Column(Integer, primary_key=True, index=True)
    rider_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False, index=True)
    driving_license_path = Column(String(255), nullable=False)
    aadhaar_card_path = Column(String(255), nullable=False)
    bank_passbook_path = Column(String(255), nullable=False)
    passport_photo_path = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False, default="pending", index=True)
    submitted_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reviewed_at = Column(DateTime, nullable=True)

    rider = relationship("User", back_populates="rider_documents")


class Vehicle(Base):
    __tablename__ = "vehicles"

    id = Column(Integer, primary_key=True, index=True)
    reg_number = Column(String(30), unique=True, index=True, nullable=False)
    battery_level = Column(Integer, default=100)
    is_available = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    rentals = relationship("Rental", back_populates="vehicle")


class Rental(Base):
    __tablename__ = "rentals"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"), nullable=False)
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)
    cost = Column(Float, default=100.0)
    status = Column(String(20), default="active")  # 'active' or 'completed'

    # Relationships
    user = relationship("User", back_populates="rentals")
    vehicle = relationship("Vehicle", back_populates="rentals")


class VehicleRequest(Base):
    __tablename__ = "vehicle_requests"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    status = Column(String(20), nullable=False, default="pending", index=True)
    requested_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    reviewed_at = Column(DateTime, nullable=True)

    user = relationship("User", back_populates="vehicle_requests")


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    type = Column(String(30), nullable=False)  # 'wallet_topup' or 'rental_fee'
    upi_ref = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="transactions")


class BreakdownReport(Base):
    __tablename__ = "breakdown_reports"

    id = Column(Integer, primary_key=True, index=True)
    rider_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    rental_id = Column(Integer, ForeignKey("rentals.id"), nullable=False, index=True)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"), nullable=False, index=True)
    description = Column(String(500), nullable=False, default="")
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    location_accuracy = Column(Float, nullable=True)
    replacement_vehicle_id = Column(Integer, ForeignKey("vehicles.id"), nullable=True)
    status = Column(String(20), nullable=False, default="open", index=True)
    reported_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    approved_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    rider = relationship("User")
    rental = relationship("Rental")
    vehicle = relationship("Vehicle", foreign_keys=[vehicle_id])
    replacement_vehicle = relationship("Vehicle", foreign_keys=[replacement_vehicle_id])