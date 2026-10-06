def test_admin_endpoint_requires_authentication(client):
    response = client.get("/admin/users")

    assert response.status_code == 401


def test_alert_status_endpoint_requires_authentication(client):
    response = client.put(
        "/alerts/1/status",
        json={"status": "investigating"},
    )

    assert response.status_code == 401


def test_normal_user_cannot_access_admin_endpoint(client):
    register_response = client.post(
        "/register",
        json={
            "username": "normaluser",
            "email": "normaluser@example.com",
            "password": "Test@1234"
        }
    )

    assert register_response.status_code in [200, 201]

    login_response = client.post(
        "/login",
        data={
            "username": "normaluser",
            "password": "Test@1234"
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.get(
        "/admin/users",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 403

    status_response = client.put(
        "/alerts/1/status",
        json={"status": "investigating"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert status_response.status_code == 404


def test_admin_user_can_access_admin_endpoint(client, db_session):
    register_response = client.post(
        "/register",
        json={
            "username": "adminuser",
            "email": "adminuser@example.com",
            "password": "Admin@1234"
        }
    )

    assert register_response.status_code in [200, 201]

    from backend.app.models.user import User

    user = (
        db_session.query(User)
        .filter(User.username == "adminuser")
        .first()
    )

    assert user is not None

    user.role = "admin"
    db_session.commit()

    login_response = client.post(
        "/login",
        data={
            "username": "adminuser",
            "password": "Admin@1234"
        }
    )

    assert login_response.status_code == 200

    token = login_response.json()["access_token"]

    response = client.get(
        "/admin/users",
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

    assert response.status_code == 200
