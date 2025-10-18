# Express Redis Session API - Curl Test Commands

## Prerequisites
Make sure your server is running on `http://localhost:3000` and Redis is running before executing these commands.

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

# Test registration with short password (should fail)
curl -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "shortpass",
    "password": "12345"
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

# Check detailed session info
curl -X GET http://localhost:3000/session-info \
  -H "Content-Type: application/json" \
  -b cookies.txt
```

## 5. Protected Routes (Authenticated Access)
```bash
# Access profile (requires authentication)
curl -X GET http://localhost:3000/profile \
  -H "Content-Type: application/json" \
  -b cookies.txt

# Access profile multiple times to increment visit count
curl -X GET http://localhost:3000/profile \
  -H "Content-Type: application/json" \
  -b cookies.txt

curl -X GET http://localhost:3000/profile \
  -H "Content-Type: application/json" \
  -b cookies.txt

# Access dashboard (requires authentication)
curl -X GET http://localhost:3000/dashboard \
  -H "Content-Type: application/json" \
  -b cookies.txt
```

## 6. Update Profile
```bash
# Update username only
curl -X PUT http://localhost:3000/update-profile \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser_updated"
  }' \
  -b cookies.txt

# Update password only
curl -X PUT http://localhost:3000/update-profile \
  -H "Content-Type: application/json" \
  -d '{
    "password": "newpassword123"
  }' \
  -b cookies.txt

# Update both username and password
curl -X PUT http://localhost:3000/update-profile \
  -H "Content-Type: application/json" \
  -d '{
    "username": "fully_updated",
    "password": "newsecurepass789"
  }' \
  -b cookies.txt

# Test update with short password (should fail)
curl -X PUT http://localhost:3000/update-profile \
  -H "Content-Type: application/json" \
  -d '{
    "password": "123"
  }' \
  -b cookies.txt

# Test update with existing username (should fail)
curl -X PUT http://localhost:3000/update-profile \
  -H "Content-Type: application/json" \
  -d '{
    "username": "john_doe"
  }' \
  -b cookies.txt
```

## 7. Protected Routes (Unauthenticated Access)
```bash
# Try to access profile without authentication
curl -X GET http://localhost:3000/profile \
  -H "Content-Type: application/json"

# Try to access dashboard without authentication
curl -X GET http://localhost:3000/dashboard \
  -H "Content-Type: application/json"

# Try to update profile without authentication
curl -X PUT http://localhost:3000/update-profile \
  -H "Content-Type: application/json" \
  -d '{
    "username": "hacker"
  }'
```

## 8. User Logout
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

## 9. Complete Test Flow Script
```bash
#!/bin/bash

echo "=== Express Redis Session API Test Flow ==="

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

echo -e "\n5. Checking detailed session info..."
curl -s -X GET http://localhost:3000/session-info -b cookies.txt | jq '.'

echo -e "\n6. Accessing profile (1st time)..."
curl -s -X GET http://localhost:3000/profile -b cookies.txt | jq '.'

echo -e "\n7. Accessing profile (2nd time - visit count++)..."
curl -s -X GET http://localhost:3000/profile -b cookies.txt | jq '.'

echo -e "\n8. Accessing dashboard..."
curl -s -X GET http://localhost:3000/dashboard -b cookies.txt | jq '.'

echo -e "\n9. Updating profile..."
curl -s -X PUT http://localhost:3000/update-profile \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser_updated"}' \
  -b cookies.txt | jq '.'

echo -e "\n10. Verifying profile update..."
curl -s -X GET http://localhost:3000/profile -b cookies.txt | jq '.'

echo -e "\n11. Logging out..."
curl -s -X POST http://localhost:3000/logout -b cookies.txt -c cookies.txt | jq '.'

echo -e "\n12. Trying to access profile after logout..."
curl -s -X GET http://localhost:3000/profile -b cookies.txt | jq '.'

echo -e "\nTest completed!"
rm -f cookies.txt
```

## 10. Advanced Testing
```bash
# Test with verbose output to see headers and session cookie
curl -v -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword123"}' \
  -c cookies.txt

# View saved cookies
cat cookies.txt

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

# Verify both sessions work independently
curl -X GET http://localhost:3000/profile -b session1.txt | jq '.'
curl -X GET http://localhost:3000/profile -b session2.txt | jq '.'

# Test session persistence in Redis
# Login, then restart server, session should persist
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "testpassword123"}' \
  -c cookies.txt

# After server restart:
curl -X GET http://localhost:3000/profile -b cookies.txt | jq '.'
```

## 11. Redis Session Verification
```bash
# While logged in, check Redis for session data
# First, get your session ID from the API
curl -s -X GET http://localhost:3000/session -b cookies.txt | jq -r '.sessionId'

# Then in Redis CLI, check the session:
# redis-cli
# KEYS sess:*
# GET sess:<your-session-id>
```

## 12. Performance Testing
```bash
# Test multiple rapid requests to same session
for i in {1..10}; do
  echo "Request $i:"
  curl -s -X GET http://localhost:3000/profile -b cookies.txt | jq '.user.visitCount'
done

# Test session creation load
for i in {1..5}; do
  curl -s -X POST http://localhost:3000/register \
    -H "Content-Type: application/json" \
    -d "{\"username\": \"user$i\", \"password\": \"password123\"}" | jq '.'
done
```

## Notes:
- **Cookie Management**: The `-c cookies.txt` flag saves cookies, and `-b cookies.txt` sends them back
- **JSON Formatting**: Add `| jq '.'` to the end of commands for pretty-printed JSON output (requires jq)
- **Session Persistence**: Sessions are stored in Redis and persist across server restarts
- **Redis Storage**: All session data is automatically saved to Redis with the configured TTL (24 hours)
- **Visit Count**: The profile endpoint increments visit count on each access
- **Password Security**: Passwords are hashed with bcrypt (10 salt rounds)
- **Error Testing**: Include tests for invalid inputs to verify error handling
- **Security**: In production, use HTTPS and secure session configuration

## Expected Response Codes:
- **200**: Successful GET/PUT requests, successful login
- **201**: Successful registration
- **400**: Bad request (missing fields, duplicate username, short password)
- **401**: Unauthorized (invalid credentials, accessing protected routes without auth)
- **404**: User not found (during profile update)
- **500**: Server error

## Session Data Stored in Redis:
```json
{
  "cookie": {
    "originalMaxAge": 86400000,
    "expires": "2025-10-19T...",
    "httpOnly": true,
    "path": "/"
  },
  "userId": "1729123456789",
  "username": "testuser",
  "loginTime": "2025-10-18T...",
  "visitCount": 3
}
```

## Cleanup
```bash
# Remove cookie files after testing
rm -f cookies.txt session1.txt session2.txt

# Clear all sessions from Redis (use with caution)
# redis-cli FLUSHDB
```