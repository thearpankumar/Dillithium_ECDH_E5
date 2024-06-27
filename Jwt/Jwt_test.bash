#!/bin/bash

# Set the login URL and the protected URL
LOGIN_URL="http://127.0.0.1:5000/login"
PROTECTED_URL="http://127.0.0.1:5000/protected"

# User credentials
USERNAME="tester"
PASSWORD="test_password"

# Function to perform login and get the token
login() {
    response=$(curl -s -X POST -F "username=$USERNAME" -F "password=$PASSWORD" $LOGIN_URL)
    echo $response
    token=$(echo $response | jq -r '.token')
    echo "Token: $token"
}

# Function to access the protected route
access_protected() {
    token=$1
    response=$(curl -s -X GET $PROTECTED_URL -H "x-access-tokens: $token")
    echo $response
}

# Perform login and get the token
login_response=$(login)
token=$(echo $login_response | jq -r '.token')

# Access the protected route using the token
access_protected $token
