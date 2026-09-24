from utils import db

c = db.get_connection()

total = c.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
analyzed = c.execute("SELECT COUNT(*) FROM logs WHERE status IS NOT NULL").fetchone()[0]
unanalyzed = c.execute("SELECT COUNT(*) FROM logs WHERE status IS NULL").fetchone()[0]
uploads = c.execute("SELECT COUNT(*) FROM uploads").fetchone()[0]

print("Total logs:", total)
print("Analyzed:", analyzed)
print("Unanalyzed:", unanalyzed)
print("Uploads:", uploads)

c.close()