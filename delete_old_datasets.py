from utils import db

BATCHES_TO_DELETE = [
    "32d0761bfd0b",  # 82,332 rows
    "6e6d9c11fb18",  # 73,784 rows
]

conn = db.get_connection()

for batch_id in BATCHES_TO_DELETE:
    logs_deleted = conn.execute(
        "DELETE FROM logs WHERE batch_id=?",
        (batch_id,)
    ).rowcount

    uploads_deleted = conn.execute(
        "DELETE FROM uploads WHERE batch_id=?",
        (batch_id,)
    ).rowcount

    print(f"{batch_id}:")
    print(f"  Logs deleted: {logs_deleted}")
    print(f"  Upload records deleted: {uploads_deleted}")

conn.commit()
conn.close()

print("\nOld datasets deleted successfully.")