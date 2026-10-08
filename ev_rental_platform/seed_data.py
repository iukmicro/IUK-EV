from app.database import SessionLocal, init_db
from app.models import User, Vehicle
from app.auth import hash_password

def seed():
    init_db()
    db = SessionLocal()

    # Create Admin
    if not db.query(User).filter(User.username == "admin").first():
        admin = User(
            username="admin",
            password_hash=hash_password("adminpass"),
            role="admin",
            is_approved=True,
            wallet_balance=0.0
        )
        db.add(admin)

    # Create Test Rider
    if not db.query(User).filter(User.username == "rider1").first():
        rider = User(
            username="rider1",
            password_hash=hash_password("riderpass"),
            role="rider",
            wallet_balance=500.0
        )
        db.add(rider)

    # Seed 100 EV Scooters
    existing_count = db.query(Vehicle).count()
    if existing_count < 100:
        for i in range(existing_count + 1, 101):
            scooter = Vehicle(
                reg_number=f"EV-BLR-{i:03d}",
                battery_level=100,
                is_available=True
            )
            db.add(scooter)

    db.commit()
    db.close()
    print("Database seeded with Admin, Rider, and 100 EV Scooters.")

if __name__ == "__main__":
    seed()