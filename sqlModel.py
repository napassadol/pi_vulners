from sqlalchemy import create_engine, Column, Integer, String, Float, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
import datetime

engine = create_engine('mysql+pymysql://networkscan:12341234@128.199.195.239/network_scan', echo = True)

Base = declarative_base()

class Nmap(Base):
    __tablename__ = 'nmap'
    id = Column(Integer, primary_key=True)
    ip = Column(String(50))
    port = Column(String(50))
    state = Column(String(50))
    service = Column(String(50))
    cve = Column(String(50))
    score = Column(Float)
    severity = Column(String(50))
    cwe = Column(String(50))
    vector = Column(String(50))
    des = Column(Text)
    os = Column(String(100))
    scan_id = Column(Integer)
    # def __repr__(self):
    #    return "<Nmap(ip='%s', port='%s', state='%s', service='%s', cve='%s', score='%s', severity='%s', cwe='%s', vector='%s', des='%s', os='%s', scan_id='%s')>" % (self.name, self.fullname, self.nickname)


class Scan(Base):
    __tablename__ = 'scan'
    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    scan_type = Column(String(100))
    date_time = Column(DateTime, default=datetime.datetime.utcnow)


class Cvss(Base):
    __tablename__ = 'cvss'
    id = Column(Integer, primary_key=True)
    version = Column(Float)
    accessComplexity = Column(String(50))
    accessVector = Column(String(50))
    authentication = Column(String(50))
    availabilityImpact = Column(String(50))
    baseScore = Column(Float)
    confidentialityImpact = Column(String(50))
    integrityImpact = Column(String(50))
    vectorString = Column(Text)
    nmap_id = Column(Integer)

Base.metadata.create_all(engine)
