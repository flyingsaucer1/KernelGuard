from flask import Flask, render_template, request
from config import cursor

app = Flask(__name__)

@app.route("/")
def dashboard():

    cursor.execute("SELECT COUNT(*) AS total FROM users")
    users = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM sessions")
    sessions = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM devices")
    devices = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM activity_events")
    events = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM alerts")
    alerts = cursor.fetchone()["total"]
    cursor.execute("""
SELECT alerts.alert_id,
       alerts.alert_type,
       alerts.severity,
       alerts.reason,
       alerts.status,
       activity_events.resource
FROM alerts
JOIN activity_events
ON alerts.event_id = activity_events.event_id
""")

    alert_list = cursor.fetchall()
    search = request.args.get("search")

    if search: 
     cursor.execute("""
        SELECT * FROM activity_events
        WHERE event_type LIKE %s
        OR process_name LIKE %s
        OR resource LIKE %s
    """, (f"%{search}%", f"%{search}%", f"%{search}%"))
    else:
     cursor.execute("SELECT * FROM activity_events")

    event_list = cursor.fetchall()
    
    return render_template(
        "dashboard.html",
        users=users,
        sessions=sessions,
        devices=devices,
        events=events,
        alerts=alerts,
        event_list=event_list,
        alert_list=alert_list
    )

if __name__ == "__main__":
    app.run(debug=True)