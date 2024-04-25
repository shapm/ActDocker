from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from cryptography.fernet import Fernet
import secrets

app = FastAPI()

# Token storage
tokens = {}

# Helper function to generate a key for encryption
def generate_key():
    return Fernet.generate_key()

# Key for encryption/decryption
key = generate_key()
cipher = Fernet(key)

class TokenData(BaseModel):
    token: str

class MessageData(BaseModel):
    token: str
    message: str

@app.get("/")
def read_root():
    return {"message": "The API is working"}

@app.post("/create-token")
def create_token():
    token = secrets.token_urlsafe(16)
    tokens[token] = True
    return {"token": token}

@app.post("/validate-token")
def validate_token(token_data: TokenData):
    if tokens.get(token_data.token):
        return {"token": token_data.token, "valid": True}
    else:
        raise HTTPException(status_code=404, detail="Token not found or invalid")

@app.post("/deactivate-token")
def deactivate_token(token_data: TokenData):
    if tokens.get(token_data.token):
        tokens[token_data.token] = False
        return {"token": token_data.token, "deactivated": True}
    else:
        raise HTTPException(status_code=404, detail="Token not found or invalid")

@app.post("/encrypt-message")
def encrypt_message(message_data: MessageData):
    if tokens.get(message_data.token):
        encrypted_message = cipher.encrypt(message_data.message.encode())
        return {"token": message_data.token, "encrypted_message": encrypted_message.decode()}
    else:
        raise HTTPException(status_code=404, detail="Invalid token")

@app.post("/decrypt-message")
def decrypt_message(message_data: MessageData):
    if tokens.get(message_data.token):
        decrypted_message = cipher.decrypt(message_data.message.encode())
        return {"token": message_data.token, "decrypted_message": decrypted_message.decode()}
    else:
        raise HTTPException(status_code=404, detail="Invalid token")

