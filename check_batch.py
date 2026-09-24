from utils import db

c = db.get_connection()

row = c.execute("""
    SELECT batch_id, filename, rows_parsed, upload_time
    FROM uploads
    ORDER BY id DESC
    LIMIT 1
""").fetchone()

print("LATEST UPLOAD:")
print(dict(row))

batch_id = row["batch_id"]

stats = c.execute("""
    SELECT
        COUNT(*) AS count,
        MIN(source_ip) AS source,
        MIN(timestamp) AS timestamp
    FROM logs
    WHERE batch_id = ?
""", (batch_id,)).fetchone()

print("\nLATEST BATCH:")
print(dict(stats))

c.close()