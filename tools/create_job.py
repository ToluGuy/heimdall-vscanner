# create_job.py

from backend.app.db import SessionLocal
from backend.app.models import Job

db = SessionLocal()

job = Job(type="nmap_scan", target="127.0.0.1")
db.add(job)
db.commit()

print("✅ Job created successfully")
