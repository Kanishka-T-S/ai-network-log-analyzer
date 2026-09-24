from utils import db

c = db.get_connection()

print("=== STATUS BY BATCH ===")

rows = c.execute("""
    SELECT batch_id, status, COUNT(*) AS count
    FROM logs
    GROUP BY batch_id, status
    ORDER BY batch_id, status
""").fetchall()

for row in rows:
    print(dict(row))


print("\n=== ANOMALY SCORE OVERALL ===")

row = c.execute("""
    SELECT
        MIN(anomaly_score) AS min_score,
        MAX(anomaly_score) AS max_score,
        AVG(anomaly_score) AS avg_score,
        COUNT(*) AS total,
        SUM(
            CASE
                WHEN anomaly_score < 0 THEN 1
                ELSE 0
            END
        ) AS negative
    FROM logs
    WHERE anomaly_score IS NOT NULL
""").fetchone()

print(dict(row))


print("\n=== ANOMALY SCORE BY STATUS ===")

rows = c.execute("""
    SELECT
        status,
        MIN(anomaly_score) AS min_score,
        MAX(anomaly_score) AS max_score,
        AVG(anomaly_score) AS avg_score,
        COUNT(*) AS count
    FROM logs
    WHERE anomaly_score IS NOT NULL
    GROUP BY status
""").fetchall()

for row in rows:
    print(dict(row))


c.close()