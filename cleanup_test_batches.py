from utils import db

KEEP_BATCH = "f0b01f4558fd"

conn = db.get_connection()

batches = conn.execute(
    "SELECT DISTINCT batch_id FROM logs WHERE status IS NULL"
).fetchall()

for row in batches:
    batch_id = row["batch_id"]

    if batch_id == KEEP_BATCH:
        continue

    logs_deleted = conn.execute(
        "DELETE FROM logs WHERE batch_id=?",
        (batch_id,)
    ).rowcount

    uploads_deleted = conn.execute(
        "DELETE FROM uploads WHERE batch_id=?",
        (batch_id,)
    ).rowcount

    print(
        f"{batch_id}: "
        f"deleted {logs_deleted} logs, "
        f"{uploads_deleted} upload record(s)"
    )

conn.commit()
conn.close()

print("\nCleanup completed.")
print(f"Keeping batch: {KEEP_BATCH}")