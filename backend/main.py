import os
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import jwt

# Google token verification
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from database import db

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "43200"))  # 30 days
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class GoogleCredential(BaseModel):
    credential: str


class UserOut(BaseModel):
    id: str
    email: str
    name: Optional[str] = None
    picture: Optional[str] = None
    provider: str = "google"


class AuthResponse(BaseModel):
    token: str
    user: UserOut


@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}


@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}


@app.post("/auth/google", response_model=AuthResponse)
def auth_google(payload: GoogleCredential):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    if not payload.credential:
        raise HTTPException(status_code=400, detail="Missing credential")

    try:
        # Verify token with Google
        request = google_requests.Request()
        idinfo = id_token.verify_oauth2_token(payload.credential, request, GOOGLE_CLIENT_ID)

        if idinfo.get("iss") not in ["accounts.google.com", "https://accounts.google.com"]:
            raise ValueError("Wrong issuer.")

        email = idinfo.get("email")
        name = idinfo.get("name")
        picture = idinfo.get("picture")
        sub = idinfo.get("sub")
        if not email:
            raise ValueError("No email in Google token")

        # Upsert user
        users = db["user"]
        now = datetime.utcnow()
        res = users.update_one(
            {"email": email},
            {
                "$set": {
                    "email": email,
                    "name": name,
                    "picture": picture,
                    "provider": "google",
                    "google_sub": sub,
                    "updated_at": now,
                },
                "$setOnInsert": {"created_at": now},
            },
            upsert=True,
        )

        doc = users.find_one({"email": email})
        user_id = str(doc.get("_id"))

        # Create JWT
        exp = datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN)
        token = jwt.encode({"sub": user_id, "email": email, "exp": exp}, JWT_SECRET, algorithm=JWT_ALG)

        return {
            "token": token,
            "user": {
                "id": user_id,
                "email": email,
                "name": name,
                "picture": picture,
                "provider": "google",
            },
        }
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid Google token: {str(e)}")


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": [],
    }

    try:
        from database import db as _db

        if _db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = _db.name if hasattr(_db, "name") else "✅ Connected"
            response["connection_status"] = "Connected"

            try:
                collections = _db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"

    except ImportError:
        response["database"] = "❌ Database module not found (run enable-database first)"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    import os as _os

    response["database_url"] = "✅ Set" if _os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if _os.getenv("DATABASE_NAME") else "❌ Not Set"

    return response


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
