from utils import db

c = db.get_connection()

print("=== SCORE SUMMARY ===")

row = c.execute("""
    SELECT
        MIN(anomaly_score) AS min_score,
        MAX(anomaly_score) AS max_score,
        AVG(anomaly_score) AS avg_score,
        COUNT(*) AS count
    FROM logs
    WHERE batch_id = '484061e39bd2'
""").fetchone()

print(dict(row))

print("\n=== SCORE RANGES ===")

rows = c.execute("""
    SELECT
        CASE
            WHEN anomaly_score < 0 THEN 'Negative'
            WHEN anomaly_score < 0.05 THEN '0-0.05'
            WHEN anomaly_score < 0.10 THEN '0.05-0.10'
            WHEN anomaly_score < 0.11 THEN '0.10-0.11'
            ELSE '>=0.11'
        END AS score_range,
        COUNT(*) AS count
    FROM logs
    WHERE batch_id = '484061e39bd2'
    GROUP BY score_range
    ORDER BY
        CASE score_range
            WHEN 'Negative' THEN 1
            WHEN '0-0.05' THEN 2
            WHEN '0.05-0.10' THEN 3
            WHEN '0.10-0.11' THEN 4
            WHEN '>=0.11' THEN 5
        END
""").fetchall()

for r in rows:
    print(dict(r))

c.close()