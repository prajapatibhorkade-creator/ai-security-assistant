def test_login_invalid_credentials(client):
    response = client.post(
        "/login",
        data={
            "username": "wronguser",
            "password": "Wrong@123"
        }
    )

    assert response.status_code in [401, 400]


def test_login_missing_password(client):
    response = client.post(
        "/login",
        data={
            "username": "testuser"
        }
    )

    assert response.status_code == 422


def test_login_success(client):
    register_response = client.post(
        "/register",
        json={
            "username": "loginuser",
            "email": "loginuser@example.com",
            "password": "Test@1234"
        }
    )

    assert register_response.status_code in [200, 201]

    response = client.post(
        "/login",
        data={
            "username": "loginuser",
            "password": "Test@1234"
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_refresh_token(client):
    register_response = client.post(
        "/register",
        json={
            "username": "refreshuser",
            "email": "refreshuser@example.com",
            "password": "Test@1234"
        }
    )

    assert register_response.status_code in [200, 201]

    login_response = client.post(
        "/login",
        data={
            "username": "refreshuser",
            "password": "Test@1234"
        }
    )

    assert login_response.status_code == 200

    login_data = login_response.json()
    refresh_token = login_data["refresh_token"]

    response = client.post(
        "/refresh",
        params={
            "refresh_token": refresh_token
        }
    )

    assert response.status_code == 200

    data = response.json()

    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_invalid_refresh_token(client):
    response = client.post(
        "/refresh",
        params={
            "refresh_token": "invalid.refresh.token"
        }
    )

    assert response.status_code == 401
