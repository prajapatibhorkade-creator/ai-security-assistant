try:
    from app.ml.behavior import analyze_login_behavior
except ModuleNotFoundError:
    from backend.app.ml.behavior import analyze_login_behavior


result = analyze_login_behavior(
    failed_attempts=12,
    known_ip=False,
    recent_event_count=80,
)

print(result)