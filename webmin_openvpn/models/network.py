from sqlalchemy import (
    Column,
    Text,
    String,
    DateTime,
    Boolean,
    func,
    )
from .meta import Base


class VPN(Base):
    __tablename__ = 'openvpn'
    nama = Column(Text, primary_key=True)
    ip = Column(String(15), nullable=False, unique=True)
    terhubung = Column(Boolean, nullable=False, server_default='false')
    perubahan = Column(
        DateTime(timezone=True), nullable=False, server_default=func.now())
    ip_sumber = Column(String(15), nullable=False)
