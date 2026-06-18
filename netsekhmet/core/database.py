import os, datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, ForeignKey, Float, Boolean, JSON, event, LargeBinary
from sqlalchemy.orm import declarative_base, sessionmaker, scoped_session, relationship
from sqlalchemy.pool import StaticPool
Base = declarative_base()

class Host(Base):
    __tablename__='hosts'
    id=Column(Integer,primary_key=True); ip_address=Column(String(45),unique=True,index=True)
    hostname=Column(String(255)); os=Column(String(100)); last_seen=Column(DateTime,default=datetime.datetime.utcnow)
    ports=relationship("Port",back_populates="host",cascade="all,delete-orphan")
    vulnerabilities=relationship("Vulnerability",back_populates="host",cascade="all,delete-orphan")
    credentials=relationship("Credential",back_populates="host",cascade="all,delete-orphan")
    sessions=relationship("Session",back_populates="host",cascade="all,delete-orphan")

class Port(Base):
    __tablename__='ports'
    id=Column(Integer,primary_key=True); host_id=Column(Integer,ForeignKey('hosts.id'),index=True)
    port_number=Column(Integer); protocol=Column(String(5)); state=Column(String(20))
    service=Column(String(100)); banner=Column(Text); version=Column(String(100))
    host=relationship("Host",back_populates="ports")

class Credential(Base):
    __tablename__='credentials'
    id=Column(Integer,primary_key=True); host_id=Column(Integer,ForeignKey('hosts.id'))
    service=Column(String(50)); username=Column(String(255)); password=Column(String(255))
    hash=Column(String(255)); domain=Column(String(255)); source=Column(String(100))
    host=relationship("Host",back_populates="credentials")

class Vulnerability(Base):
    __tablename__='vulnerabilities'
    id=Column(Integer,primary_key=True); host_id=Column(Integer,ForeignKey('hosts.id'))
    cve=Column(String(30)); title=Column(String(255)); description=Column(Text)
    severity=Column(Integer); cvss=Column(Float); exploit_available=Column(Boolean,default=False)
    exploit_path=Column(String(500)); status=Column(String(50),default="unexploited")
    host=relationship("Host",back_populates="vulnerabilities")

class Session(Base):
    __tablename__='sessions'
    id=Column(Integer,primary_key=True); host_id=Column(Integer,ForeignKey('hosts.id'))
    session_type=Column(String(50)); session_id=Column(String(100),unique=True)
    status=Column(String(20),default="active"); created_at=Column(DateTime,default=datetime.datetime.utcnow)
    payload_used=Column(String(100)); tunnel_info=Column(JSON, default={})
    host=relationship("Host",back_populates="sessions")

class OperationLog(Base):
    __tablename__='operation_logs'
    id=Column(Integer,primary_key=True); timestamp=Column(DateTime,default=datetime.datetime.utcnow)
    module=Column(String(100)); action=Column(String(200)); target=Column(String(255))
    result=Column(Text); status=Column(String(20))

class Screenshot(Base):
    __tablename__='screenshots'
    id=Column(Integer,primary_key=True); host_id=Column(Integer,ForeignKey('hosts.id'))
    image=Column(LargeBinary); captured_at=Column(DateTime,default=datetime.datetime.utcnow)

class Keystroke(Base):
    __tablename__='keystrokes'
    id=Column(Integer,primary_key=True); host_id=Column(Integer,ForeignKey('hosts.id'))
    text=Column(Text); timestamp=Column(DateTime,default=datetime.datetime.utcnow)

DB_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'db', 'netsekhmet.db')
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
engine = create_engine(f'sqlite:///{DB_PATH}', connect_args={'check_same_thread':False}, poolclass=StaticPool, pool_size=5)
SessionLocal = scoped_session(sessionmaker(bind=engine))

@event.listens_for(engine, "connect")
def set_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

def init_db(): Base.metadata.create_all(engine)
def get_db(): return SessionLocal()

from contextlib import contextmanager
@contextmanager
def db_session():
    db = SessionLocal()
    try: yield db; db.commit()
    except: db.rollback(); raise
    finally: db.close()

def store_host(db, ip, hostname="", os=""):
    host = db.query(Host).filter_by(ip_address=ip).first()
    if not host:
        host = Host(ip_address=ip, hostname=hostname, os=os, last_seen=datetime.datetime.utcnow())
        db.add(host); db.commit()
    else:
        host.last_seen = datetime.datetime.utcnow()
        if hostname: host.hostname = hostname
        if os: host.os = os
        db.commit()
    return host

def store_port(db, host, port_num, protocol, state, service="", banner="", version=""):
    existing = db.query(Port).filter_by(host_id=host.id, port_number=port_num, protocol=protocol).first()
    if existing: existing.state=state; existing.service=service; existing.banner=banner; existing.version=version
    else: db.add(Port(host_id=host.id, port_number=port_num, protocol=protocol, state=state, service=service, banner=banner, version=version))
    db.commit()

def store_credential(db, host, username, password="", hash="", domain="", service="", source=""):
    db.add(Credential(host_id=host.id, service=service, username=username, password=password, hash=hash, domain=domain, source=source))
    db.commit()

def store_vulnerability(db, host, cve, title, description="", severity=3, cvss=0.0, exploit_available=False):
    existing = db.query(Vulnerability).filter_by(host_id=host.id, cve=cve).first()
    if not existing:
        db.add(Vulnerability(host_id=host.id, cve=cve, title=title, description=description, severity=severity, cvss=cvss, exploit_available=exploit_available))
        db.commit()

def store_session(db, host, session_type, session_id, payload_used="", tunnel_info={}):
    db.add(Session(host_id=host.id, session_type=session_type, session_id=session_id, payload_used=payload_used, tunnel_info=tunnel_info))
    db.commit()

def log_operation(db, module, action, target, result="", status="success"):
    db.add(OperationLog(module=module, action=action, target=target, result=result, status=status))
    db.commit()

init_db()
