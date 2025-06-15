# Express Authentication API - Curl Test Commands

## Prerequisites
Make sure your server is running on `http://localhost:3000` before executing these commands.

## 1. Check API Status
```bash
# Test the root endpoint
curl -X GET http://localhost:3000/ \
  -H "Content-Type: application/json" \
  -c cookies.txt
```

## 2. User Registration
```bash
# Register a new user
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "testpassword123"
  }' \
  -c cookies.txt

# Register another user for testing
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe",
    "password": "securepass456"
  }' \
  -c cookies.txt

# Test registration with missing fields
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "incomplete"
  }' \
  -c cookies.txt

# Test registration with existing username
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "anotherpassword"
  }' \
  -c cookies.txt
```

## 3. User Login
```bash
# Login with valid credentials
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "testpassword123"
  }' \
  -c cookies.txt \
  -b cookies.txt

# Test login with invalid credentials
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "wrongpassword"
  }' \
  -c cookies.txt

# Test login with non-existent user
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "nonexistent",
    "password": "somepassword"
  }' \
  -c cookies.txt

# Test login with missing fields
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser"
  }' \
  -c cookies.txt
```

## 4. Session Management
```bash
# Check session status (before login)
curl -X GET http://localhost:3000/session \
  -H "Content-Type: application/json"

# Check session status (after login)
curl -X GET http://localhost:3000/session \
  -H "Content-Type: application/json" \
  -b cookies.txt
```

## 5. Protected Routes (Authenticated Access)
```bash
# Access profile (requires authentication)
curl -X GET http://localhost:3000/profile \
  -H "Content-Type: application/json" \
  -b cookies.txt

# Access dashboard (requires authentication)
curl -X GET http://localhost:3000/dashboard \
  -H "Content-Type: application/json" \
  -b cookies.txt
```

## 6. Protected Routes (Unauthenticated Access)
```bash
# Try to access profile without authentication
curl -X GET http://localhost:3000/profile \
  -H "Content-Type: application/json"

# Try to access dashboard without authentication
curl -X GET http://localhost:3000/dashboard \
  -H "Content-Type: application/json"
```

## 7. User Logout
```bash
# Logout user (requires authentication)
curl -X POST http://localhost:3000/logout \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -c cookies.txt

# Try to access protected route after logout
curl -X GET http://localhost:3000/profile \
  -H "Content-Type: application/json" \
  -b cookies.txt
```

## 8. Complete Test Flow Script
```bash
#!/bin/bash

echo "=== Express Auth API Test Flow ==="

echo -e "\n1. Testing API Status..."
curl -s -X GET http://localhost:3000/ -c cookies.txt | jq '.'

echo -e "\n2. Registering new user..."
curl -s -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword123"}' \
  -c cookies.txt | jq '.'

echo -e "\n3. Logging in..."
curl -s -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword123"}' \
  -c cookies.txt -b cookies.txt | jq '.'

echo -e "\n4. Checking session..."
curl -s -X GET http://localhost:3000/session -b cookies.txt | jq '.'

echo -e "\n5. Accessing profile..."
curl -s -X GET http://localhost:3000/profile -b cookies.txt | jq '.'

echo -e "\n6. Accessing dashboard..."
curl -s -X GET http://localhost:3000/dashboard -b cookies.txt | jq '.'

echo -e "\n7. Logging out..."
curl -s -X POST http://localhost:3000/logout -b cookies.txt -c cookies.txt | jq '.'

echo -e "\n8. Trying to access profile after logout..."
curl -s -X GET http://localhost:3000/profile -b cookies.txt | jq '.'

echo -e "\nTest completed!"
```

## 9. Advanced Testing
```bash
# Test with verbose output to see headers
curl -v -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword123"}' \
  -c cookies.txt

# Test with form data instead of JSON
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=formuser&password=formpass123" \
  -c cookies.txt

# Test concurrent sessions (use different cookie files)
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword123"}' \
  -c session1.txt

curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "john_doe", "password": "securepass456"}' \
  -c session2.txt
```

## Notes:
- **Cookie Management**: The `-c cookies.txt` flag saves cookies, and `-b cookies.txt` sends them back
- **JSON Formatting**: Add `| jq '.'` to the end of commands for pretty-printed JSON output (requires jq)
- **Session Persistence**: Cookies are essential for maintaining session state between requests
- **Error Testing**: Include tests for invalid inputs to verify error handling
- **Security**: In production, use HTTPS and secure session configuration

## Expected Response Codes:
- **200**: Successful GET requests, successful login
- **201**: Successful registration
- **400**: Bad request (missing fields, duplicate username)
- **401**: Unauthorized (invalid credentials, accessing protected routes without auth)
- **500**: Server error