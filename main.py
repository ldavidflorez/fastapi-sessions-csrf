from fastapi import FastAPI, Depends, HTTPException, Header, Cookie, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware  # Import the CORSMiddleware
import uuid  # Import the uuid module

app = FastAPI()

# In-memory storage for sessions. In a production environment, use a database or caching system.
session_storage = {}

# In-memory storage for CSRF tokens.
csrf_storage = {}

# In-memory storage for simplicity. In a production environment, use a database.
fake_users_db = {
    "testuser": {
        "username": "testuser",
        "password": "testpassword"
    }
}

# Session cookie name
SESSION_COOKIE_NAME = "session_token"

# CSRF cookie name
CSRF_COOKIE_NAME = "csrf_token"


# Dependency to get the CSRF token from the cookie
def get_csrf_token(csrf_token: str = Header(None)):
    if csrf_token is None or csrf_token not in csrf_storage:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token validation failed",
        )
    return csrf_token


# Dependency to get the current user from the session storage
async def get_current_user(session_token: str = Cookie(None), csrf_token: str = Depends(get_csrf_token)):
    if session_token is None or session_token not in session_storage:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"session_token": session_token, "csrf_token": csrf_token}


@app.post("/login")
async def login_for_access_token(response: JSONResponse, form_data: OAuth2PasswordRequestForm = Depends()):
    username = form_data.username
    password = form_data.password
    if username in fake_users_db and fake_users_db[username]["password"] == password:
        # Generate a session token using UUID
        session_token = str(uuid.uuid4())

        # Generate a CSRF token
        csrf_token = str(uuid.uuid4())

        # Store the session data on the server side
        session_storage[session_token] = {"username": username}

        # Store CSRF token on the server side
        csrf_storage[csrf_token] = {"username": username}

        # Set a session cookie with the session token and CSRF token
        response.set_cookie(key=SESSION_COOKIE_NAME,
                            value=session_token, httponly=True)
        response.set_cookie(key=CSRF_COOKIE_NAME,
                            value=csrf_token, httponly=False)

        return {"message": "Login successful"}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.post("/logout")
async def logout(response: JSONResponse, current_user: dict = Depends(get_current_user)):
    # Clear the session data from the server side
    del session_storage[current_user["session_token"]]

    # Clear the session data from the server side
    del csrf_storage[current_user["csrf_token"]]

    # Clear the session cookie to log out
    response.delete_cookie(SESSION_COOKIE_NAME)
    # Clear CSRF tokens
    response.delete_cookie(CSRF_COOKIE_NAME)
    return {"message": "Logout successful"}


@app.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {"message": "This is a protected route"}


# Include CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # You can specify specific origins instead of "*"
    allow_credentials=True,
    allow_methods=["*"],  # You can specify specific HTTP methods
    allow_headers=["*"],  # You can specify specific headers
)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
