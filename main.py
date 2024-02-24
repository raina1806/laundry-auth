from fastapi import FastAPI, Depends, HTTPException
from starlette.responses import RedirectResponse
from config import CLIENT_ID, CLIENT_SECRET, secret_key
from fastapi.security import OAuth2PasswordBearer
import requests
import jwt

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Replace these with your own values from the Google Developer Console
GOOGLE_CLIENT_ID = CLIENT_ID
GOOGLE_CLIENT_SECRET = CLIENT_SECRET
GOOGLE_REDIRECT_URI = "http://localhost:8000/auth/google"
SECRET_KEY = secret_key

@app.get("/login/google")
async def login_google():
    return RedirectResponse(url=f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&scope=openid%20profile%20email&access_type=offline")

@app.get("/auth/google")
async def auth_google(code: str):
    token_url = "https://accounts.google.com/o/oauth2/token"
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    response = requests.post(token_url, data=data)
    access_token = response.json().get("access_token")
    user_info = requests.get("https://www.googleapis.com/oauth2/v1/userinfo", headers={"Authorization": f"Bearer {access_token}"})

    # Check if the user_info request was successful
    if user_info.status_code != 200:
        raise HTTPException(status_code=user_info.status_code, detail="Failed to fetch user information")

    # Encode user information as JWT token using PyJWT
    user_info_dict = user_info.json()
    jwt_token = jwt.encode({"sub": user_info_dict["id"], "username": user_info_dict["email"]}, SECRET_KEY, algorithm="HS256")

    # Return JWT token in the response
    return {"access_token": jwt_token, "token_type": "bearer"}

@app.get("/token")
async def get_token(token: str = Depends(oauth2_scheme)):
    try:
        # Attempt to decode and verify the token using PyJWT
        decoded_token = jwt.decode(token, GOOGLE_CLIENT_SECRET, algorithms=["HS256"])
        return decoded_token
    except jwt.ExpiredSignatureError:
        # Handle expired token
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError as e:
        # Handle other JWT decoding errors
        raise HTTPException(status_code=401, detail="Invalid token")

@app.get("/")
async def home():
    return {"msg": "auth done"}

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
