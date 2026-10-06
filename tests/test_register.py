def test_register_user(client):
    response = client.post(
        "/register",
        json={
            "username": "testuser",
            "email": "testuser@example.com",
            "password": "Test@1234"
        }
    )

    assert response.status_code in [200, 201]
    data = response.json()

    assert data["username"] == "testuser"
    assert data["email"] == "testuser@example.com"


def test_register_invalid_email(client):
    response = client.post(
        "/register",
        json={
            "username": "testuser456",
            "email": "invalid-email",
            "password": "Test@1234"
        }
    )

    assert response.status_code == 422


def test_register_weak_password(client):
    response = client.post(
        "/register",
        json={
            "username": "weakuser",
            "email": "weak@example.com",
            "password": "123"
        }
    )

    assert response.status_code == 400
