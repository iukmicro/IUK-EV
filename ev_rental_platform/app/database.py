from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = "sqlite:///./fleet.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def init_db(target_engine=engine):
    Base.metadata.create_all(bind=target_engine)
    with target_engine.begin() as connection:
        migrations = {
            "users": {
                "full_name": "VARCHAR(100)",
                "mobile_number": "VARCHAR(20)",
                "password_reset_required": "BOOLEAN NOT NULL DEFAULT 0",
                "account_status": "VARCHAR(20) NOT NULL DEFAULT 'active'",
            },
            "breakdown_reports": {
                "latitude": "FLOAT",
                "longitude": "FLOAT",
                "location_accuracy": "FLOAT",
                "replacement_vehicle_id": "INTEGER REFERENCES vehicles(id)",
                "approved_at": "DATETIME",
            },
        }
        inspector = inspect(connection)
        for table_name, columns in migrations.items():
            if not inspector.has_table(table_name):
                continue
            existing_columns = {
                column["name"]
                for column in inspector.get_columns(table_name)
            }
            for column_name, column_type in columns.items():
                if column_name not in existing_columns:
                    connection.execute(text(
                        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
                    ))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()