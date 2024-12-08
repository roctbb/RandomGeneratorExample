import requests

URL = 'http://127.0.0.1:8000'


def register_request(login, password):
    return requests.post(
        URL + '/api/register',
        json={
            "login": login,
            "password": password
        }
    )


def login_request(login, password):
    return requests.post(
        URL + '/api/login',
        json={
            "login": login,
            "password": password
        }
    )

def get_number(token):
    return requests.get(
        URL + '/api/generate',
        headers={
            "Authorization": f"Bearer {token}"
        }
    )

if __name__ == '__main__':
    register_response = register_request("Lupa", "123456")
    assert register_response.status_code == 201

    login_response = login_request("Lupa", "123456")
    assert login_response.status_code == 200

    token = login_response.json()['token']

    number_response = get_number(token)
    print(number_response.json())
    assert number_response.status_code == 200
    print(number_response.json()['number'])

