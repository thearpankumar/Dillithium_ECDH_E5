import requests

# Set the URLs
LOGIN_URL = "http://127.0.0.1:5000/login"
PROTECTED_URL = "http://127.0.0.1:5000/protected"

# User credentials
USERNAME = "tester"
PASSWORD = "test_password"


# Perform login and get the token
def login():
    data = {
        'username': USERNAME,
        'password': PASSWORD
    }
    response = requests.post(LOGIN_URL, data=data)
    if response.status_code == 200:
        token = response.json().get('token')
        return token
    else:
        print(f"Failed to log in. Status code: {response.status_code}")
        return None


# Access the protected route using the token
def access_protected(token):
    headers = {
        'x-access-tokens': token
    }
    response = requests.get(PROTECTED_URL, headers=headers)
    if response.status_code == 200:
        message = response.json().get('message')
        print(f"Protected Route Response: {message}")
    else:
        print(f"Failed to access protected route. Status code: {response.status_code}")


# Main execution
if __name__ == "__main__":
    # Perform login and get the token
    token = login()

    if token:
        # Access the protected route using the token
        access_protected(token)
