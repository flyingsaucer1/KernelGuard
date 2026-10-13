from flask import Flask, render_template, request
from config import cursor

app = Flask(__name__)

@app.route("/")
def dashboard():
    cursor.execute("SELECT COUNT(*) AS total FROM alerts WHERE severity='High'")
    high_alerts = cursor.fetchone()["total"]
  
    cursor.execute("SELECT COUNT(*) AS total FROM alerts WHERE severity='Medium'")
    medium_alerts = cursor.fetchone()["total"]

    cursor.execute("SELECT COUNT(*) AS total FROM alerts WHERE severity='Low'")
    low_alerts = cursor.fetchone()["total"]
    
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
    cursor.execute("""
    SELECT event_type, process_name, event_time
    FROM activity_events
    ORDER BY event_time DESC
    LIMIT 5
    """)
    recent_events = cursor.fetchall()

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
        alert_list=alert_list,
        recent_events=recent_events,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        low_alerts=low_alerts,
    )
print("Users route loaded")
@app.route("/users")
def users():

    search = request.args.get("search")

    if search:
        cursor.execute("""
            SELECT * FROM users
            WHERE username LIKE %s
            OR role LIKE %s
        """, (f"%{search}%", f"%{search}%"))
    else:
        cursor.execute("SELECT * FROM users")

    user_list = cursor.fetchall()

    return render_template(
        "users.html",
        user_list=user_list
    )
@app.route("/alerts")
def alerts_page():

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

    return render_template(
        "alerts.html",
        alert_list=alert_list
    )
@app.route("/devices")
def devices_page():

    cursor.execute("SELECT * FROM devices")
    device_list = cursor.fetchall()

    return render_template(
        "devices.html",
        device_list=device_list
    )
@app.route("/sessions")
def sessions_page():

    cursor.execute("""
        SELECT * FROM sessions
    """)

    session_list = cursor.fetchall()

    return render_template(
        "sessions.html",
        session_list=session_list
    )
@app.route("/event/<int:event_id>")
def event_details(event_id):

    cursor.execute("""
        SELECT *
        FROM activity_events
        WHERE event_id=%s
    """,(event_id,))

    event = cursor.fetchone()

    return render_template(
        "event_details.html",
        event=event
    )
if __name__ == "__main__":
    app.run(debug=True)