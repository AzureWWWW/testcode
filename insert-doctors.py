from main import SessionLocal, Doctor

def insert_doctors():
    db = SessionLocal()
    doctors_data = [
        {"name": "Dr. John Smith", "specialization": "Cardiologist"},
        {"name": "Dr. Jane Doe", "specialization": "Neurologist"},
        {"name": "Dr. Alice Brown", "specialization": "Pediatrician"},
        {"name": "Dr. Robert Wilson", "specialization": "Orthopedic"},
        {"name": "Dr. Emma Davis", "specialization": "Dermatologist"},
        {"name": "Dr. Michael Clark", "specialization": "Ophthalmologist"},
        {"name": "Dr. Olivia Martinez", "specialization": "ENT Specialist"},
        {"name": "Dr. William Garcia", "specialization": "Oncologist"},
        {"name": "Dr. Sophia Lee", "specialization": "Psychiatrist"},
        {"name": "Dr. James White", "specialization": "General Physician"}
    ]

    for doctor_data in doctors_data:
        existing_doctor = db.query(Doctor).filter_by(name=doctor_data["name"]).first()
        if not existing_doctor:
            new_doctor = Doctor(name=doctor_data["name"], specialization=doctor_data["specialization"])
            db.add(new_doctor)
    db.commit()
    db.close()

insert_doctors()