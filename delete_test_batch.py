from utils import db

BATCH_ID = "05ab2bc8cda2"

c = db.get_connection()

# Delete logs belonging only to this batch
deleted_logs = c.execute(
    "DELETE FROM logs WHERE batch_id = ?",
    (BATCH_ID,)
).rowcount

# Delete the corresponding upload history entry
deleted_upload = c.execute(
    "DELETE FROM uploads WHERE batch_id = ?",
    (BATCH_ID,)
).rowcount

c.commit()
c.close()

print("Deleted logs:", deleted_logs)
print("Deleted upload records:", deleted_upload)
