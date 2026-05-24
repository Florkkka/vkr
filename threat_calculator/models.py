import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = "sqlite:///threat_calculator.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    type = Column(String(50), nullable=False)
    protocols = Column(String(200), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "protocols": self.protocols.split(",") if self.protocols else [],
            "protocols_str": self.protocols or "",
            "description": self.description or "",
            "created_at": self.created_at.isoformat() if self.created_at else "",
        }


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(300), nullable=False)
    stride = Column(String(1), nullable=False)
    description = Column(Text, nullable=True)
    asset_id = Column(Integer, nullable=True)
    asset_name = Column(String(200), nullable=True)
    probability = Column(Integer, nullable=False, default=1)
    impact = Column(Integer, nullable=False, default=1)
    risk_score = Column(Integer, nullable=False, default=1)
    risk_level = Column(String(20), nullable=False, default="низкий")
    recommendation = Column(Text, nullable=True)
    mitigated = Column(Boolean, default=False)
    is_custom = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "stride": self.stride,
            "description": self.description or "",
            "asset_id": self.asset_id,
            "asset_name": self.asset_name or "",
            "probability": self.probability,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "recommendation": self.recommendation or "",
            "mitigated": self.mitigated,
            "is_custom": self.is_custom,
            "created_at": self.created_at.isoformat() if self.created_at else "",
        }


def init_db():
    Base.metadata.create_all(bind=engine)
    return SessionLocal()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
