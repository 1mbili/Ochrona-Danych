import pytest
from app.app import create_app

@pytest.fixture()
def app():
    app = create_app()
    # other setup can go here
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def runner(app):
    return app.test_cli_runner()

def test_no_existing_endpoint_request_example(client):
    response = client.get("/authorize")
    assert "404 NOT FOUND" in repr(response)


def test_get_simple_authorize(client):
    response = client.get("/authenticate")
    assert all(x in str(response.data) for x in ['username', 'password', 'register', 'auth', 'anonymous_view', 'authenticate', 'restore_acces'])


def test_post_simple_authorize(client):
    response = client.post("/authenticate", data={
     "username" : "Janusz",
     "password" : "Tracz"
    })
    assert response.request.path == "/authenticate"


def test_post_empty_username_authorize(client):
    response = client.post("/authenticate", data={
     "username" : "",
     "password" : "admin"
    })
    assert response.request.path == "/authenticate"


def test_post_empty_password_authorize(client):
    response = client.post("/authenticate", data={
     "username" : "admin",
     "password" : ""
    })
    assert response.request.path == "/authenticate"


def test_login_correctly(client):
    response = client.post("/authenticate", data={
     "username" : "admin",
     "password" : "admin"
    })
    assert response.status_code == 200
