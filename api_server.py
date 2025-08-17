# api_server.py
#modified from : https://saptak.in
import os
import asyncio
import json
import uuid
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse, HTMLResponse
import uvicorn
from dotenv import load_dotenv
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

from google.adk import Runner
from google.adk.sessions import DatabaseSessionService, Session
from google.auth.transport.requests import Request as GoogleAuthRequest
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from google.genai import types
from google.cloud import secretmanager

import firebase_admin
from firebase_admin import credentials, firestore



# Allow insecure transport for local development (OAUTHLIB requirement).
# This should be commented out or removed for production deployment.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


# Import your agents
import agent  # Update with your actual imports


def access_secret_payload(project_id: str, secret_id: str, version_id: str = "latest") -> str:
    """
    Access the payload for the given secret version and return it.
    """
    try:
        # Create the Secret Manager client.
        client = secretmanager.SecretManagerServiceClient()

        # Build the resource name of the secret version.
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"

        # Access the secret version.
        response = client.access_secret_version(request={"name": name})

        payload = response.payload.data.decode("UTF-8")
        return payload
    except Exception as e:
        print(f"Error accessing secret: {e}")
        return None

def credentials_to_dict(credentials):
    """Helper function to convert Google credentials to a dictionary."""
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

async def get_client_config():
    return client_config

# --- OAuth2 Configuration ---
# The redirect URI must match exactly what you have in the Google Cloud Console.
REDIRECT_URI_INDEX = 2 #change to 1 for production
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
]

class QueryRequest(BaseModel):
    query: str
    user_id: str = "default_user"
    session_id: str = None

class QueryResponse(BaseModel):
    response: str
    session_id: str

def set_client_config(project_id, oauth_client_id, oauth_client_secret):

    secret_status = ""
    if not project_id:
        raise HTTPException(status_code=500, detail="GOOGLE_CLOUD_PROJECT environment variable not set.")

    if project_id:
        oauth_client_id_value = access_secret_payload(project_id, oauth_client_id)
        oauth_client_secret_value = access_secret_payload(project_id, oauth_client_secret)
 
        if not oauth_client_id_value:
            raise HTTPException(status_code=500, detail="Could not access value of oauth client ID '{oauth_client_id}'. Check permissions and if the secret exists.\n")

        if not oauth_client_secret_value:
            raise HTTPException(status_code=500, detail="Could not access secret value of  '{oauth_client_secret}'. Check permissions and if the secret exists.")

        client_config = {
            "web": {
                "client_id": oauth_client_id_value,
                "project_id": project_id,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_secret": oauth_client_secret_value,
                "redirect_uris": [
                    "http://localhost:8080/callback",
                    "https://cp220-grader-api-zuqb5siaua-el.a.run.app/callback",
                    "https://8080-cs-b88a9ebf-4d62-464d-a6bf-38908d2cb297.cs-asia-southeast1-yelo.cloudshell.dev/callback"
                ],
            }
        }
        return client_config


# Load environment variables at the top
load_dotenv()

project_id = os.environ.get("GOOGLE_CLOUD_PROJECT")
#get secrets from google's secrets manager
oauth_client_id = "CP220-OAUTH-CLIENT-ID" 
oauth_client_secret = "CP220-OAUTH-CLIENT-SECRET"
signing_secret_key = access_secret_payload(project_id, "CP220-SIGNING-SECRET-KEY")
if not signing_secret_key:
    raise HTTPException(status_code=400, detail="Cant access CP220-SIGNING-SECRET-KEY")

#access the keys related to firestore database
firestore_key_id = access_secret_payload(project_id,"CP220-FIRESTORE-PRIVATE-KEY-ID")

#secrets manager stores private key with '\n' escaped as '\\n'. we need to undo this.
firestore_key = access_secret_payload(project_id,"CP220-FIRESTORE-PRIVATE-KEY").replace('\\n', '\n')
if not firestore_key_id or not firestore_key:
    raise HTTPException(status_code=400, detail="Cant access CP220-FIRESTORE KEYS")

#construct the credentials to access the database
firestore_cred_dict = {
    "type": "service_account",
    "project_id": project_id,
    "private_key_id": firestore_key_id,
    "private_key": firestore_key,
    "client_email": "cp220-firestore@cp220-grading-assistant.iam.gserviceaccount.com",
    "client_id": "101156988112383641306",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/cp220-firestore%40cp220-grading-assistant.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
}

print(firestore_cred_dict)

# Initialize Firebase Admin
cred = credentials.Certificate(firestore_cred_dict)
firebase_admin.initialize_app(cred)

client_config = set_client_config(project_id, oauth_client_id, oauth_client_secret)


database_id = "cp220-2025"
try:
    db = firestore.client(database_id=database_id)
except Exception as e:
    print(f"Error connecting to Firestore: {e}")
    exit(1)
users_ref = db.collection('users')
docs = users_ref.stream()

for doc in docs:
    print(f'{doc.id} => {doc.to_dict()}')


def get_client_config():
    return client_config


app = FastAPI(title="CP220-2025 Agent API")

# Add the session middleware
# The secret_key is used to sign the session cookie for security.
app.add_middleware(
    SessionMiddleware,
    secret_key=signing_secret_key # Use an environment variable for this in production!
)


@app.get("/login", tags=["Authentication"])
async def login(request: Request, client_config:dict = Depends(get_client_config)):
    """
    Redirects the user to the Google OAuth consent screen to initiate login.
    """
    flow = Flow.from_client_config(
        client_config=client_config,
        scopes=SCOPES,
        redirect_uri=client_config['web']['redirect_uris'][REDIRECT_URI_INDEX]
    )

    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    # Store the state in the user's session to verify it in the callback, preventing CSRF.
    request.session['state'] = state

    return RedirectResponse(authorization_url)

@app.get("/callback", tags=["Authentication"])
async def oauth_callback(request: Request,client_config:dict = Depends(get_client_config)):
    """
    Handles the callback from Google after user consent.
    Exchanges the authorization code for credentials and creates a user session.
    """
    state = request.session.get('state')
    if not state or state != request.query_params.get('state'):
        raise HTTPException(status_code=400, detail="State mismatch, possible CSRF attack.")


    flow = Flow.from_client_config(
        client_config=client_config, 
        scopes=SCOPES, 
        redirect_uri=client_config['web']['redirect_uris'][REDIRECT_URI_INDEX]
        )
    flow.fetch_token(authorization_response=str(request.url))

    flow_creds = flow.credentials
    # Store credentials and user info in the session.
    # In a real app, you might store credentials in a database linked to the user.
    request.session['credentials'] = credentials_to_dict(flow_creds)
    userinfo_service = build('oauth2', 'v2', credentials=flow_creds)
    request.session['user'] = userinfo_service.userinfo().get().execute()

    return {"message": f"Hi {request.session['user']['name']} You have successfully logged in. Happy solving!"}

@app.post("/query", response_model=QueryResponse)
async def process_query(request: QueryRequest):
    try:
        # Get or create session ID
        #print(f"Received request: {request.query}")
        session_id = request.session_id or str(uuid.uuid4())

        # Check if session exists
        existing_sessions = await session_service.list_sessions(
            app_name="CP220_2025_Grader_Agent_API",
            user_id=request.user_id
        )

        # Extract existing session IDs
        if not existing_sessions:
            existing_session_ids = []
        else:
            # Ensure existing_sessions is a list of session objects
            if not isinstance(existing_sessions, list):
                existing_sessions = [existing_sessions]
            # Extract session IDs from the session objects
            # This assumes each session object has an 'id' attribute
            # Adjust this line if your session objects have a different structure
            if hasattr(existing_sessions[0], 'id'):              
                existing_session_ids = [session.id for session in existing_sessions]

        if not request.session_id or request.session_id not in existing_session_ids:
            # Create a new session
            await session_service.create_session(
                app_name="CP220_2025_Grader_Agent_API",
                user_id=request.user_id,
                session_id=session_id
            )

        # Create a message from the query

        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=request.query)]
        )

        #print(f"Processing query: {request.query} for user: {request.user_id}, session: {session_id}")

        # Run the agent
        response = runner.run_async(
            user_id=request.user_id,
            session_id=session_id,
            new_message=content
        )

        # Extract the response text
        response_text:str = ""
        #for event in response:
        #    if event.type == "content" and event.content.role == "agent":
        #        response_text = event.content.parts[0].text
        #        break
        async for event in response:
            #print(f"Event received: {event}")
            if event.content and event.content.parts:
                for part in event.content.parts:
                    #print(f"Agent Response: {part.text}")
                    response_text += ";\n" + part.text
            elif event.is_final_response():
                print("Agent finished processing.")
            break # Exit loop after final response
    
        if not response_text:
            raise HTTPException(status_code=500, detail="Failed to generate response")

        #print(f"Final response: {response_text}")
        return QueryResponse(
            response=response_text,
            session_id=session_id
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/", tags=["Authentication"], response_class=HTMLResponse)
async def root():
    """
    Serves a simple login page with a button to initiate Google OAuth login.
    """
    html_content = """
    <html>
        <head>
            <title>Login to CP220-2025 Grader API</title>
        </head>
        <body>
            <h1>Welcome to CP220-2025 Lab Session!</h1>
            <p>Please log in to use the CP220 Grading Assistant.</p>
            <form action="/login" method="get">
                <button type="submit" style="padding: 10px 20px; font-size: 16px; cursor: pointer;">Login with Google</button>
            </form>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content, status_code=200)

@app.get("/profile")
async def profile(request: Request):
    # The middleware reads the cookie from the request and loads the session data.
    print(request.session)
    user_id = request.session['user']['id']
    user_name = request.session['user']['name']
    if not user_id:
        return {"error": "Not logged in"}
    return {"user_id": user_id, "username": user_name}
    


# Define or import root_agent
root_agent = agent.root_agent  # Update this line if your agent module uses a different name or structure


# Create a database session service
session_service = DatabaseSessionService(
    db_url="sqlite:///agent_sessions.db"
)

# Create a runner with your agents
runner = Runner(
    app_name="CP220_2025_Grader_Agent_API",
    agent=root_agent,  # Add all your agents here
    session_service=session_service
)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    #uvicorn.run(app, host="127.0.0.1", port=port)
    uvicorn.run(app, host="0.0.0.0", port=port) #allow access from any IP address