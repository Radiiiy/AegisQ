from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# --- DATABASE SETUP ---
# SQLite database file will be created automatically in your project folder
DATABASE_URL = "sqlite:///./aegisq_history.db"

engine = create_engine(
    DATABASE_URL, connect_args={"check_same_thread": False}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- SCAN RECORD TABLE ---
class ScanRecord(Base):
    """
    This is like a blueprint for one row in your scan history table.
    Every scan gets saved as one row with these columns.
    """
    __tablename__ = "scan_records"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    scan_type = Column(String)      # "QR_IMAGE" or "DIRECT_URL"
    scanned_url = Column(String)    # The URL that was scanned
    overall_status = Column(String) # "SECURE" or "THREAT DETECTED"
    vision_result = Column(String)  # "SAFE", "DANGEROUS", or "N/A"
    vision_confidence = Column(Float)
    url_result = Column(String)     # "SAFE", "MALICIOUS", "UNKNOWN"
    url_confidence = Column(Float)
    explanation_summary = Column(String)  # SHAP summary if available

# --- CREATE THE TABLE ---
def init_db():
    """Creates the database table if it doesn't exist yet."""
    Base.metadata.create_all(bind=engine)
    print("AegisQ: Database initialized.")

# --- SAVE A SCAN ---
def save_scan(
    scan_type: str,
    scanned_url: str,
    overall_status: str,
    vision_result: str,
    vision_confidence: float,
    url_result: str,
    url_confidence: float,
    explanation_summary: str = None
):
    """Saves one scan result to the database."""
    db = SessionLocal()
    try:
        record = ScanRecord(
            scan_type=scan_type,
            scanned_url=scanned_url,
            overall_status=overall_status,
            vision_result=vision_result,
            vision_confidence=vision_confidence,
            url_result=url_result,
            url_confidence=url_confidence,
            explanation_summary=explanation_summary
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record
    except Exception as e:
        db.rollback()
        print(f"AegisQ: Failed to save scan record: {e}")
        return None
    finally:
        db.close()

# --- GET SCAN HISTORY ---
def get_history(limit: int = 50):
    """Returns the most recent scan records."""
    db = SessionLocal()
    try:
        records = db.query(ScanRecord)\
            .order_by(ScanRecord.timestamp.desc())\
            .limit(limit)\
            .all()
        return records
    finally:
        db.close()

# --- GET STATS ---
def get_stats():
    """Returns summary statistics about all scans."""
    db = SessionLocal()
    try:
        total = db.query(ScanRecord).count()
        threats = db.query(ScanRecord)\
            .filter(ScanRecord.overall_status == "THREAT DETECTED")\
            .count()
        secure = db.query(ScanRecord)\
            .filter(ScanRecord.overall_status == "SECURE")\
            .count()
        return {
            "total_scans": total,
            "threats_detected": threats,
            "secure_scans": secure,
            "threat_percentage": round((threats / total * 100), 2) if total > 0 else 0
        }
    finally:
        db.close()