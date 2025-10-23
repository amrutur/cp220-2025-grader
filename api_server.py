#api_server.py
''' 
An api server to access the AI agent for grading answers submitted via
Google Colab Notebook cell.

The Colab users need to be authenticated via Google's Oauth2 service

The instructor can optionally provide a rubric file to help assist
the AI agent in grading and providing hints for answers, as well as provide
marks. The rubric file has to be shared with a service account

It logs the interactions in a Firsestore NoSQl database

Two environment parameters are requred:
GOOGLE_CLOUD_PROECT (should be set to be the project id for the application google cloud)
PRODUCTION (should be set to 0 for local testing and 1 for production)

In addition a google service account is needed to access the firestore database as
well as the rubric (the rubric file has to be shared with the service account)

All the secrets are accessed from the api_server's owner's secret manager on google.

Written with lots of help from google's gemini !

'''

import os
import sys

from google.cloud import secretmanager
import asyncio

import logging
import traceback
import json
import uuid
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

import uvicorn
from dotenv import load_dotenv
from pydantic import BaseModel, AnyUrl, EmailStr
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import RedirectResponse

from google.adk import Runner
from google.adk.sessions import DatabaseSessionService, Session
from google.adk.agents import Agent

from google.auth.transport.requests import Request as GoogleAuthRequest
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload

import google.generativeai as genai
from google.genai import types

import firebase_admin
from firebase_admin import credentials, firestore

import io
import re
from typing import  Dict, List, Any
import datetime
import pytz

from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import base64
from email.mime.text import MIMEText

#logging configuration


# 1. Define the format for the logs
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - [%(funcName)s] - %(message)s')

# 2. Create a Console Handler (outputs to terminal/console)
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
console_handler.setLevel(logging.INFO) # Only show INFO, WARNING, ERROR on console

# 3. Create a File Handler (outputs to a log file)
file_handler = logging.FileHandler('app.log', mode='a')
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.DEBUG) # Show all DEBUG messages in the file

# 4. Get the root logger and attach the handlers
root_logger = logging.getLogger()
root_logger.addHandler(console_handler)
root_logger.addHandler(file_handler)

# Set the overall logging level to DEBUG
#logging.basicConfig(level=logging.DEBUG)
root_logger.setLevel(logging.DEBUG)


# Set specific loggers for Starlette/ADK to DEBUG if needed
#logging.getLogger("starlette").setLevel(logging.INFO)
#logging.getLogger("google_adk").setLevel(logging.DEBUG) 

# Note: Using logging.DEBUG will flood your console with internal steps, 
# which is perfect for debugging agent logic.


# Disable the assist API during this time window
# should be made configurable via environment variables
# or via firestore database in the future
ASSIST_API_DISABLE_START = datetime.datetime(2025, 10, 6,12,00,00)
ASSIST_API_DISABLE_END = datetime.datetime(2025, 10, 6,17,0,00)


def access_secret_payload(project_id: str, secret_id: str, version_id: str = "latest") -> str:
    """
    Access the payload for the given secret version from google secret manager 
    and return it.
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
        print(f"Error accessing secret: {e}", file=sys.stderr)
        return None


def load_app_config():
    """Loads all configuration from environment variables and Secret Manager, then initializes services."""
    load_dotenv()

    # --- Helper functions for loading ---
    def get_required_env(var_name):
        value = os.environ.get(var_name)
        if not value:
            print(f"Error: Required environment variable '{var_name}' is not set.", file=sys.stderr)
            sys.exit(1)
        return value

    project_id = get_required_env("GOOGLE_CLOUD_PROJECT")

    def get_required_secret(key_name_env_var):
        secret_name = get_required_env(key_name_env_var)
        payload = access_secret_payload(project_id, secret_name)
        if not payload:
            print(f"Error: Could not retrieve secret '{secret_name}' from Secret Manager for project '{project_id}'.", file=sys.stderr)
            sys.exit(1)
        return payload

    # --- Load all required values ---
    is_production = os.environ.get('PRODUCTION', '0') == '1'
    database_id = get_required_env('FIRESTORE_DATABASE_ID')
    oauth_client_id = get_required_secret('OAUTH_CLIENT_ID_KEY_NAME')
    oauth_client_secret = get_required_secret('OAUTH_CLIENT_SECRET_KEY_NAME')
    signing_secret_key = get_required_secret('SIGNING_SECRET_KEY_NAME')
    firestore_key_id = get_required_secret('FIRESTORE_PRIVATE_KEY_ID_KEY_NAME')
    firestore_key_raw = get_required_secret('FIRESTORE_PRIVATE_KEY_KEY_NAME')
    gemini_api_key = get_required_secret('GEMINI_API_KEY_NAME')

    # --- Configure services ---
    if not is_production:
        os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
        print("Running in development mode. Insecure OAUTH callback enabled.")

    # --- Construct configuration dictionaries ---
    firestore_key = firestore_key_raw.replace('\\n', '\n')
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

    client_config = {
        "web": {
            "client_id": oauth_client_id,
            "project_id": project_id,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_secret": oauth_client_secret,
            "redirect_uris": [
                "http://localhost:8080/callback",
                "https://cp220-grader-api-zuqb5siaua-el.a.run.app/callback",
                "https://b5ee73f0d420.ngrok-free.app/callback"
            ],
        }
    }

    # Determine the correct redirect URI based on production status
    redirect_uri_index = 1 if is_production else 2

    return {
        "project_id": project_id,
        "database_id": database_id,
        "signing_secret_key": signing_secret_key,
        "firestore_cred_dict": firestore_cred_dict,
        "client_config": client_config,
        "redirect_uri_index": redirect_uri_index,
        "gemini_api_key": gemini_api_key
    }



# --- Application Startup ---
config = load_app_config()

# Initialize Firebase Admin with loaded credentials
try:
    cred = credentials.Certificate(config["firestore_cred_dict"])
    firebase_admin.initialize_app(cred)
    db = firestore.client(database_id=config["database_id"])
except Exception as e:
    print(f"Fatal Error: Could not initialize Firebase/Firestore. {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)



# Authenticate
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.send']
gmail_flow = InstalledAppFlow.from_client_secrets_file('credentials.json', GMAIL_SCOPES)
gmail_creds = gmail_flow.run_local_server(port=0)

# Build Gmail service
email_service = build('gmail', 'v1', credentials=gmail_creds)


client_config = config["client_config"]
signing_secret_key = config["signing_secret_key"]
REDIRECT_URI_INDEX = config["redirect_uri_index"]
firestore_cred_dict = config["firestore_cred_dict"]

os.environ['GOOGLE_API_KEY'] = str(config["gemini_api_key"])

# Import your agents
import agent  # Update with your actual imports
# Define or import agents
root_agent = agent.root_agent  # Update this line if your agent module uses a different name or structure
scoring_agent=agent.scoring_agent

# Create a database session service
session_service = DatabaseSessionService(
    db_url="sqlite:///agent_sessions.db"
)

# Create a runner with your agents
runner_assist = Runner(
    app_name="CP220_2025_Grader_Agent_API",
    agent=root_agent,  # Add all your agents here
    session_service=session_service
)
runner_score = Runner(
    app_name="CP220_2025_Scoring_Agent_API",
    agent=scoring_agent,  # Add all your agents here
    session_service=session_service
)

def credentials_to_dict(credentials):
    """Helper function to convert Google credentials to a dictionary."""
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

# --- OAuth2 Configuration ---
# The redirect URI must match exactly what you have in the Google Cloud Console.
SCOPES = [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
    "https://www.googleapis.com/auth/drive.readonly",  # Add scope to read Google Drive files
    'https://www.googleapis.com/auth/gmail.send', #send email
]

class QueryRequest(BaseModel):
    query: str
    course_id: str
    notebook_id: str
    q_name: str
    rubric_link: AnyUrl | None = None
    user_name: str | None = None
    user_email: str | None = None
 
class QueryResponse(BaseModel):
    response: str

class AssistRequest(BaseModel):
    query: str
    q_id: str
    rubric_link: AnyUrl | None = None
    user_name: str | None = None
    user_email: str | None = None

 
class AssistResponse(BaseModel):
    response: str

class GradeRequest(BaseModel):
    question: str
    answer: str
    rubric: str
    course_id: str | None = None
    notebook_id: str | None = None
    q_id: str | None = None
    user_name: str | None = None
    user_email: str | None = None
 
class GradeResponse(BaseModel):
    response: str
    marks: float

class EvalRequest(BaseModel):
    course_id: str
    user_name: str 
    user_email: str
    notebook_id: str
    answer_notebook: Dict[str, Any]
    answer_hash: str
    rubric_link: AnyUrl


class EvalResponse(BaseModel):
    response: str
    marks: float

class FetchGradedRequest(BaseModel):
    notebook_id: str
    user_email: EmailStr

class FetchGradedResponse(BaseModel):
    grader_response: Dict[str, Any] | None = None

class NotifyGradedRequest(BaseModel):
    notebook_id: str
    user_email: EmailStr

class NotifyGradedResponse(BaseModel):
    response: str

class FetchStudentListRequest(BaseModel):
    course_id:str | None = None
    notebook_id: str | None = None

class FetchStudentListResponse(BaseModel):
    response: Dict[str, Any]| None = None

def get_user_list(db):
    '''return the list of users in the firestore database'''
    users_ref = db.collection('users')
    docs = users_ref.select([]).stream()
    user_list  = []

    for doc in docs:
        user_list.append(doc.id)

    return user_list

def add_user_if_not_exists(db, google_user_id, user_name, user_email, google_user_name):
    '''add the user to the firestore database if not already present'''
    user_list = get_user_list(db)

    if google_user_id not in user_list:
        logging.info(f"User '{user_name}' ({google_user_id}) not in database. Adding now.")
        user_ref = db.collection(u'users').document(google_user_id)
        user_ref.set({
            u'name': user_name,
            u'email': user_email,
            u'google_user_name': google_user_name
        })

def add_answer_notebook(db, google_user_id, notebook_id, answer_notebook, answer_hash):
    '''add the answer notebook to the firestore database'''
    try:
        answer_ref = db.collection(u'users').document(google_user_id).collection(u'notebooks').document(notebook_id)
        answer_ref.set({
            u'answer_notebook': answer_notebook,
            u'answer_hash': answer_hash,
            u'submitted_at': firestore.SERVER_TIMESTAMP      
        })
    except Exception as e:
        logging.error(f"Error adding answer notebook to Firestore: {e}")
        #traceback.print_exc()

def update_marks(db, google_user_id, notebook_id, total_marks, max_marks,graded):
    '''update the marks for the answer notebook of google_user_id in the firestore database'''
    try:
        answer_ref = db.collection(u'users').document(google_user_id).collection(u'notebooks').document(notebook_id)
        answer_ref.set({
            u'total_marks': total_marks,
            u'max_marks': max_marks,
            u'graded_at': firestore.SERVER_TIMESTAMP      
        },merge=True)
        # Also update the graded details
        answer_ref.set({
            u'graded': graded
        },merge=True)
    except Exception as e:
        logging.error(f"Error updating marks in Firestore: {e}")
        #traceback.print_exc()


app = FastAPI(title="CP220-2025 Agent API")

origins = [
    "http://localhost",
    "http://localhost:8080",
    "*",
    # You can also use "*" to allow all origins
]

#app.add_middleware(
#    CORSMiddleware,
#    allow_origins=["*"],  # Allows all origins
#    allow_credentials=True,
#    allow_methods=["*"],
#    allow_headers=["*"],
#)


# Add the session middleware
# The secret_key is used to sign the session cookie for security.
app.add_middleware(
    SessionMiddleware,
    secret_key=signing_secret_key # Use an environment variable for this in production!
)


@app.get("/login", tags=["Authentication"])
#async def login(request: Request, client_config:dict = Depends(get_client_config)):
async def login(request: Request):
    """
    Redirects the user to the Google OAuth consent screen to initiate login.
    """
    print("Request Headers:", request.headers)
    print("Client Host:", request.client.host)    

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
#async def oauth_callback(request: Request,client_config:dict = Depends(get_client_config)):
async def oauth_callback(request: Request):
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

    user_id = request.session['user']['id']
    user_name = request.session['user']['name']
    user_list = get_user_list(db)

    if user_id not in user_list:
        print(f"User '{user_name}' ({user_id}) not in database. Adding now.")
        user_ref = db.collection(u'users').document(user_id)
        user_ref.set({
            u'name': user_name,
            u'email': request.session['user'].get('email')
        })

    return {"message": f"Hi {request.session['user']['name']} You have successfully logged in. Happy solving!"}

@app.get("/logout", tags=["Authentication"])
async def logout(request: Request):
    """
    Logs the user out by clearing their session.
    """
    request.session.clear()
    html_content = "You have been logged out. <a href='/'>Login again</a>"
    return HTMLResponse(content=html_content)


def get_file_id_from_share_link(share_link: str) -> str or None:
    """
    Extracts the file ID from a Google Drive share link.

    Args:
        share_link: The Google Drive share link.

    Returns:
        The file ID as a string, or None if the link is invalid.
    """
    try:
        # Split the link by '/'
        parts = share_link.split('/')

        #print('from get_file_id_from_share_link', parts)

        # Find the index of 'd' or 'drive' which usually precedes the file ID
        if 'd' in parts:
            d_index = parts.index('d')
        elif 'drive' in parts:
            d_index = parts.index('drive')
        else:
            raise IndexError
        
        # The file ID is usually the next part after 'd'
        file_id = parts[d_index + 1]
        subparts = file_id.split('?')
        file_id = subparts[0]

        return file_id
    except ValueError:
        print("Invalid share link format.")
        return None
    except IndexError:
        print("Could not extract file ID from the share link.")
        return None

def get_notebook_content_from_link_sa(service_account_info: dict, file_id: str):
    """
    Downloads content of a google colab notebook from a given file_id using a service account.

    Args:
        service_account_info: A dictionary of the service account credentials.
        file_id : file_id of the notebook

    Returns:
        The content of the notebook as a string, or None if not found.
    """
    try:
        from google.oauth2 import service_account

        scopes = ["https://www.googleapis.com/auth/drive.readonly"]
        credentials = service_account.Credentials.from_service_account_info(service_account_info, scopes=scopes)
        drive_service = build('drive', 'v3', credentials=credentials)

        # Download the file content
        request = drive_service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()

        # The content is in fh; decode it as UTF-8
        notebook_content = fh.getvalue().decode('utf-8')
        return notebook_content

    except HttpError as error:
        print(f"An HTTP error occurred while accessing Google Drive with Service Account: {error}")
        if error.resp.status == 404:
            print(f"Error 404: File with ID '{file_id}' not found. Check the file ID and that it's shared with the service account.")
        elif error.resp.status == 403:
            print(f"Error 403: Permission denied for file ID '{file_id}'. Ensure the Drive API is enabled and the service account has permissions.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred in get_notebook_content_from_link_sa: {e}")
        return None

def load_notebook_from_google_drive_sa(service_account_info: dict, share_link: str):
    """
    Loads a Colab notebook from Google Drive given its share link, using a service account.

    Args:
        service_account_info: A dictionary containing the service account credentials.
        share_link: The shareable link to the Colab notebook on Google Drive.

    Returns:
        The content of the notebook as a string, or None if it cannot be loaded.
    """
    file_id = get_file_id_from_share_link(share_link)
    if not file_id:
        print("Could not extract file ID from share link.")
        return None
    return get_notebook_content_from_link_sa(service_account_info, file_id)



async def run_agent_and_get_response(current_session_id: str, user_id: str, content: types.Content, runner:Runner) -> str:
    """Helper to run the agent and aggregate the response text from the stream."""
    response_stream = runner.run_async(
        user_id=user_id,
        session_id=current_session_id,
        new_message=content,
    )

    text = ""
    async for event in response_stream:
        if event.content and event.content.parts:
            for part in event.content.parts:
                text += part.text
                #print(f"Received part: {part.text}")
        if event.is_final_response():
            break

    
    #print(f"Final aggregated response: {text}")
    return text

@app.post("/assist", response_model=AssistResponse)
async def assist(query_body: AssistRequest, request: Request):

    #check if the this API is disabled currently
    now_utc = datetime.datetime.now(pytz.utc)
    now_ist = now_utc.astimezone(pytz.timezone('Asia/Kolkata'))
    if ASSIST_API_DISABLE_START.date() <= now_ist.date() and \
        now_ist.date()  <= ASSIST_API_DISABLE_END.date() and \
        ASSIST_API_DISABLE_START.time() <= now_ist.time() and \
        now_ist.time()  <= ASSIST_API_DISABLE_END.time():
        raise HTTPException(status_code=503, detail="The assist API is temporarily disabled during quiz. Please try again later.")

   # print("Processing Query")
    runner = runner_assist

    if ('user' in request.session) : #user is logged and authenticated
        user_id = request.session['user']['id']
    else:
        user_id = query_body.user_email if query_body.user_email else "anonymous_user"

    user_name = query_body.user_name if query_body.user_name else "Anonymous User"

    #if 'user' not in request.session:
    #    raise HTTPException(status_code=401, detail="User not authenticated. #Please login first.")

    try:
        # Use a consistent session ID for the agent conversation

        if 'agent_session_id' in request.session:
            session_id = request.session.get('agent_session_id')
        else:
            session_id = str(uuid.uuid4())
            request.session['agent_session_id'] = session_id
            await session_service.create_session(
                    app_name=runner.app_name,
                    user_id=user_id,
                    session_id=session_id
                )

        rubric = ''

        if query_body.rubric_link:
            # Read rubric notebook using the application's service account, not the logged-in user's credentials.
            #print(f"rubric link is {query_body.rubric_link}")
            notebook_content = await asyncio.to_thread(
                load_notebook_from_google_drive_sa, firestore_cred_dict, str(query_body.rubric_link)
            )
            if notebook_content is None:
                raise HTTPException(
                    status_code=404, detail=f"Rubric notebook '{query_body.rubric_link}' not found. Ensure it is shared with the service account: {firestore_cred_dict.get('client_email')}"
                )

            try:
                # .ipynb files are JSON, so we can return them as JSON
                notebook_json = json.loads(notebook_content)
                #print(json.dumps(notebook_json, indent=2))
                #return JSONResponse(content=notebook_json)
            except json.JSONDecodeError:
                # Or return as plain text if it's not valid JSON for some reason
                return HTMLResponse(content=f"<pre>Could not parse rubric notebook as JSON. Raw content:\n\n{notebook_content}</pre>")
            rubric =  "The rubric is: " + ''.join(notebook_json['cells'][q_id+1]['source'])
        # Create a message from the query
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=query_body.query+rubric)]
        )

        # Attempt to get the response using the current session ID
        response_text = await run_agent_and_get_response(session_id,user_id, content,runner)

        if not response_text:
            raise HTTPException(status_code=500, detail="Failed to generate response")

        return AssistResponse(
            response=response_text
            )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during query processing: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.post("/query", response_model=QueryResponse)
async def process_query(query_body: QueryRequest, request: Request):


    #check if the this API is disabled currently
    now_utc = datetime.datetime.now(pytz.utc)
    now_ist = now_utc.astimezone(pytz.timezone('Asia/Kolkata'))
    if ASSIST_API_DISABLE_START.date() <= now_ist.date() and \
        now_ist.date()  <= ASSIST_API_DISABLE_END.date() and \
        ASSIST_API_DISABLE_START.time() <= now_ist.time() and \
        now_ist.time()  <= ASSIST_API_DISABLE_END.time():
        raise HTTPException(status_code=503, detail="The assist API is temporarily disabled during quiz. Please try again later.")

   # print("Processing Query")
    runner = runner_assist

    #if 'user' not in request.session:
    #    raise HTTPException(status_code=401, detail="User not authenticated. #Please login first.")

    try:
        # Use a consistent session ID for the agent conversation
        #logging.info(request.session)
        session_id = request.session.get('agent_session_id', str(uuid.uuid4()))
        request.session['agent_session_id'] = session_id

        #user_id = request.session['user']['id']
        #user_name = request.session['user']['name']

        user_id = query_body.user_email if query_body.user_email else "anonymous_user"
        user_name = query_body.user_name if query_body.user_name else "Anonymous User"

        # Create a message from the query
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=query_body.query)]
        )

        logging.info(f"User {user_name}, has asked for checking for question {query_body.q_name} in course {query_body.course_name} and notebook={query_body.notebook_name}")        

        if query_body.rubric_link:
            # Read rubric notebook using the application's service account, not the logged-in user's credentials.
            #print(f"rubric link is {query_body.rubric_link}")
            notebook_content = await asyncio.to_thread(
                load_notebook_from_google_drive_sa, firestore_cred_dict, str(query_body.rubric_link)
            )
            if notebook_content is None:
                raise HTTPException(
                    status_code=404, detail=f"Rubric notebook '{query_body.rubric_link}' not found. Ensure it is shared with the service account: {firestore_cred_dict.get('client_email')}"
                )

            try:
                # .ipynb files are JSON, so we can return them as JSON
                notebook_json = json.loads(notebook_content)
                #print(json.dumps(notebook_json, indent=2))
                #return JSONResponse(content=notebook_json)
            except json.JSONDecodeError:
                # Or return as plain text if it's not valid JSON for some reason
                return HTMLResponse(content=f"<pre>Could not parse notebook as JSON. Raw content:\n\n{notebook_content}</pre>")


        try:
            # Attempt to get the response using the current session ID
            response_text = await run_agent_and_get_response(session_id,user_id, content,runner)
        except ValueError as e:
            # This error indicates the session ID in the cookie is stale or invalid.
            if "Session not found" in str(e):
                print(f"Stale session ID '{session_id}' detected. Creating and retrying with a new session.")
                # Create a new session ID
                new_session_id = str(uuid.uuid4())
                # Explicitly create the new session in the database before using it.
                await session_service.create_session(
                    app_name=runner.app_name,
                    user_id=user_id,
                    session_id=new_session_id
                )
                request.session['agent_session_id'] = new_session_id
                response_text = await run_agent_and_get_response(new_session_id, user_id, content,runner)
            else:
                # Re-raise any other ValueError that is not a session not found error.
                raise

        if not response_text:
            raise HTTPException(status_code=500, detail="Failed to generate response")

        #print(f"Agent response: {response_text}")

        return QueryResponse(
            response=response_text
            )

    except KeyError:
        raise HTTPException(status_code=401, detail="Invalid session data. Please login again.")
    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during query processing: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")

async def score_question(question:str, answer:str, rubric:str, runner:Runner, request: Request, user_id: str) -> tuple[float,str]:
    '''
    Score a single question-answer with the rubric using the scoring agent
    
    Inputs:
    question: The question asked
    answer: The student's answer
    rubric: The rubric to be used for grading
    runner: The runner with the scoring agent
    request: The FastAPI request object (to access session)
    user_id: The user ID of the student

    Outputs:
    marks: The marks awarded
    response_text: The agent's response

    '''


    try:

        #create a new session to avoid any context carryover
        session_id = str(uuid.uuid4())
        request.session['agent_session_id'] = session_id
        await session_service.create_session(
                    app_name=runner.app_name,
                    user_id=user_id,
                    session_id=session_id
            )


        question = "The assignment question is: " + question + "."
        answer = "The student's answer is: " + answer + "."
        rubric = "The rubric is: " + rubric +"."

        # Create the prompt content
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=question + answer + rubric)]
        )

        # Attempt to get the response using the current session ID
        response_text = await run_agent_and_get_response(session_id,user_id, content,runner)

    except Exception as e:
        logging.error(f"Error in score_question: {e}")
        raise HTTPException(status_code=500, detail=f"An internal error occurred while scoring: {e}")

    if not response_text:
        raise HTTPException(status_code=500, detail="Agent failed to generate response")


    #extract the marks from the response text
    marks = 0.0
    marks_pattern = r"total\s+marks\D+(\d+\.?\d*)"
    marks_match = re.search(marks_pattern, response_text, re.IGNORECASE)
    if marks_match:
        marks = float(marks_match.group(1))
    else:
        raise HTTPException(status_code=500, detail="Agent failed to extract marks")

    return marks, response_text

@app.post("/grade", response_model=GradeResponse)
async def grade(query_body: GradeRequest, request: Request):

    '''Grade a single question-answer'''
    runner = runner_score

    #if 'user' not in request.session:
    #    raise HTTPException(status_code=401, detail="User not authenticated. #Please login first.")

    if ('user' in request.session) : #user is logged and authenticated
        user_id = request.session['user']['id']
    else:
        user_id = query_body.user_email if query_body.user_email else "anonymous_user"

    user_name = query_body.user_name if query_body.user_name else "Anonymous User"


    try:
        # Use a consistent session ID for the agent conversation

        if 'agent_session_id' in request.session:
            session_id = request.session.get('agent_session_id')
        else:
            session_id = str(uuid.uuid4())
            request.session['agent_session_id'] = session_id
            await session_service.create_session(
                    app_name=runner.app_name,
                    user_id=user_id,
                    session_id=session_id
                )

        if not query_body.question:
            raise HTTPException(status_code=400, detail="Question not provided")
          
        question =  query_body.question + "."
        answer = query_body.answer + "." if query_body.answer else "No answer."
        rubric =  query_body.rubric if query_body.rubric else "No rubric"

        marks, response_text = await score_question(question, answer, rubric, runner, session_id, user_id)

        return GradeResponse(
            response=response_text,
            marks = marks
        )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during query processing: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


async def evaluate(answer_json, rubric_json, runner:Runner, request: Request, user_id: str)-> tuple[float,float,int,dict]:
    '''Evaluate the submitted notebook by grading all questions using the scoring agent'''
    try:
        acells = answer_json['cells']
        rcells = rubric_json['cells']
        total_marks = 0.0
        max_marks = 0.0
        num_questions = 0

        qpattern = r"\*\*Q(\d+)\*\*\s*\((\d+\.?\d*)"

        #extract the questions from the rubric cells and match with the answer cells
        i = 0
        questions = {}
        rubrics={}
        graded={} #graders response and marks
        #print(f"Total cells in rubric notebook: {len(rcells)}")
        qmax_marks = {}
        while i < len(rcells) :
            if rcells[i]['cell_type'] == 'markdown':
                #check if it is a question cell
                #print(f"Checking rubric cell {i} for question pattern.{''.join(rcells[i].get('source', []))}")
                qmatch = re.search(qpattern, ''.join(rcells[i].get('source', [])))
                if qmatch:
                    qnum = int(qmatch.group(1))
                    qmarks = float(qmatch.group(2))
                    qmax_marks[qnum]=qmarks
                    max_marks += qmarks
                    num_questions += 1
                    questions[qnum]=''.join(rcells[i].get('source', []))
                    logging.debug(f"Cell {i} qnum={qnum} with max marks {qmarks}")
                    i += 1
                    #next cell should be the rubric cell
                    if i < len(rcells):
                        rubrics[qnum]=''.join(rcells[i].get('source', []))
                    else:
                        raise Exception(f"Rubric cell missing after question {qnum}")
                
            i += 1
        logging.info(f"Extracted {num_questions} questions from rubric notebook with total marks {max_marks}. Now grading answers.")
        i=0
        while i < len(acells):
            #rint(f"Checking answer cell {i} for question pattern")
            if acells[i]['cell_type'] == 'markdown':
                #check if it is a question cell
                qmatch = re.search(r"\*\*Q(\d+)\*\*", ''.join(acells[i].get('source', [])))
                if qmatch:
                    qnum = int(qmatch.group(1))
                    i+=1
                    if i < len(acells) and acells[i]['cell_type'] == 'markdown':
                        answer=''.join(acells[i].get('source', []))
                    else:
                        answer="No answer provided."
                    logging.debug(f"scoring question {qnum} for user {user_id}")
                    logging.debug(f"Question: {questions[qnum]}")
                    marks, response_text = await score_question(questions[qnum], answer, rubrics[qnum], runner, request, user_id)
                    total_marks += marks
                    graded[qnum] = {'marks': marks, 'response': response_text}
                    logging.info(f"Graded question {qnum}: awarded {marks}/{qmax_marks[qnum]} marks.")
                    if marks > qmax_marks[qnum]:
                        logging.error(f"Error: Awarded marks {marks} exceeds maximum {qmax_marks[qnum]} for question {qnum}.")
            i += 1
        return total_marks, max_marks, num_questions, graded

    except Exception as e:
        print(f"Error during evaluation: {e}", file=sys.stderr)
        traceback.print_exc()


@app.post("/eval", response_model=EvalResponse)
async def eval_submission(query_body: EvalRequest, request: Request):
    '''Evaluate the submitted notebook by grading all questions using the scoring agent'''
    
    runner= runner_score

    try:

        if not query_body.user_name or not  query_body.user_email or not query_body.answer_notebook or not query_body.rubric_link or not query_body.answer_hash:
            raise HTTPException(status_code=400, detail="Incomplete request. Please provide user_name, user_email, answer_notebook, asnwer_hash and rubric_link")
        
        #user_id = request.session['user']['id']
        #user_name = request.session['user']['name']

        user_email = query_body.user_email 
        user_name = query_body.user_name

        answer_notebook = query_body.answer_notebook          
        answer_hash = query_body.answer_hash
        rubric_link = query_body.rubric_link

        try:
            # .ipynb files are JSON, so we can return them as JSON
            #answer_json = json.loads(answer_notebook)
            answer_json = answer_notebook
        except json.JSONDecodeError:
            # Or return as plain text if it's not valid JSON for some reason
            return HTMLResponse(content=f"<pre>Could not parse notebook as JSON. Raw content:\n\n</pre>")


        #extract the cells from the notebook
        if ('ipynb' in answer_json): #remove one hierarchy if present
            answer_json = answer_json['ipynb']
        
        answer_cells = answer_json['cells'] if 'cells' in answer_json else []
        #print(f"answr cell 1 is {answer_cells[1]}")
        #extract google validated name, and id.
        #This is stored in the metadata of the execution info for any code  cell of the notebook
        for i in range(len(answer_cells)):
            cell = answer_cells[i]
            if cell['cell_type'] == 'code' and  cell['metadata']['executionInfo']['status'] == 'ok':
                    google_user_name = cell['metadata']['executionInfo']['user']['displayName']
                    google_user_id = cell['metadata']['executionInfo']['user']['userId']
                    break

        if not google_user_name:
            google_user_name = "Unknown"
            google_user_id = "Unknown"
            logging.warning("Warning: Could not extract google user name and id from notebook metadata.Need to run at least one code cell")

        #Temporary DEBUG
        if (re.search(r'Amrutur',google_user_name,re.IGNORECASE)):
            google_user_name = user_name
            google_user_id = user_email
    
        logging.info(f"google_user_name={google_user_name}, google_user_id={google_user_id}")

        add_user_if_not_exists(db, google_user_id, user_name, user_email, google_user_name)

        add_answer_notebook(db, google_user_id, query_body.notebook_id, answer_notebook, answer_hash)

        # Read rubric notebook using the application's service account, not the logged-in user's credentials.
        logging.info(f"rubric link is {query_body.rubric_link}")
        rubric_content = await asyncio.to_thread(
            load_notebook_from_google_drive_sa, firestore_cred_dict, str(rubric_link)
        )
        if rubric_content is None:
            raise HTTPException(
                status_code=404, detail=f"{user_name:user_email} Rubric notebook '{rubric_link}' not found. Ensure it is shared with the service account: {firestore_cred_dict.get('client_email')}"
            )
        try:
            # .ipynb files are JSON, so we can return them as JSON
            rubric_json = json.loads(rubric_content)
            #print(json.dumps(rubri_jsocn, indent=2))
            #return JSONResponse(content=rubric_json)
        except json.JSONDecodeError:
            # Or return as plain text if it's not valid JSON for some reason
            return HTMLResponse(content=f"<pre>Could not parse notebook as JSON. Raw content:\n</pre>")
        #

        #print(f"Rubric notebook successfully loaded as {rubric_json}")

        try: 
            total_marks,max_marks,num_questions,graded = await evaluate(answer_json, rubric_json, runner, request, google_user_id)

            logging.info(f"{google_user_name}: Evaluation completed. Total Marks: {total_marks}/{max_marks} for {num_questions} questions.")
            #print(f"Graded details: {graded}")

            graded_string = json.dumps(graded, indent=2)
            update_marks(db, google_user_id, query_body.notebook_id, total_marks, max_marks, graded_string)

            return EvalResponse(
                response=google_user_name + ": You have successfully submitted notebook for evaluation. Graded answer will be sent to your email.",
                marks = 0.0
            )
        except Exception as e:
            # By logging the exception with its traceback, you can see the root cause in your server logs.
            logging.error("An exception occurred during query processing: %s", e)
            traceback.print_exc()

    except KeyError:
        raise HTTPException(status_code=401, detail="Invalid session data. Please login again.")
    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during query processing: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


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

def fetch_grader_response(db, notebook_id:str=None, user_email:str=None):
    '''
    get the graded answer for the student user_email for notebook_id in the firestore database
    '''

    logging.debug(f"Fetching grader response for email: {user_email} and notebook_id: {notebook_id}")

    try:
        user_list = get_user_list(db)
        grader_response={}

        if notebook_id is None:
            logging.error(f"notebook_id is None")
            return None
        for user_id in user_list:
            answer_ref = db.collection(u'users').document(user_id).collection(u'notebooks').document(notebook_id)
            userinfo_ref = db.collection(u'users').document(user_id)
            logging.debug(f"Fetched userinfo_ref for {user_email}")
            userinfo_doc = userinfo_ref.get()
            logging.debug(f"Fetched userinfo_doc for {userinfo_doc.get('name')} with {userinfo_doc.get('email')} ")
            answer_doc = answer_ref.get()
            logging.debug(f"Checking user: {userinfo_doc.get('name')} with {userinfo_doc.get('email')} ")
            if  re.match(f"{user_email}",userinfo_doc.get('email'),re.IGNORECASE) is None:
                logging.debug(f"No match for email {user_email} and {userinfo_doc.get('email')}")
                continue
            logging.debug(f"Found matching user: {userinfo_doc.get('name')} with {userinfo_doc.get('email')} ")

            user_name = userinfo_doc.get('name')
            logging.debug(f"Fetching graded response for user: {user_name} and notebook_id: {notebook_id}")
            response_json = answer_doc.to_dict()

            logging.debug(f"user:{user_name} : total marks: {response_json.get('total_marks')} Response json: {response_json.get('graded')}")

            grader_response = {'user_name':user_name, 'total_marks':response_json.get('total_marks'),'max_marks':response_json.get('max_marks')}

            grader_response['feedback'] = json.loads(response_json.get('graded'))
            logging.debug(f"For  matching user, response is: {grader_response}")
            break
        return grader_response
    except Exception as e:
        logging.error(f"Error in fetch_grader_response: {e}")
        #traceback.print_exc()

@app.post("/fetch_grader_response", response_model=FetchGradedResponse)
async def fetch_grader_response_api(query_body: FetchGradedRequest, request: Request):
    '''Fetch the graded response for a student from the database'''
    try:

        if not query_body.notebook_id:
            raise HTTPException(status_code=400, detail="notebook_id not provided")

        if not query_body.user_email:
            raise HTTPException(status_code=400, detail="user_email not provided")

        user_email = query_body.user_email

        logging.debug(f"Fetching grader response for email: {user_email} and notebook_id: {query_body.notebook_id}")
        grader_response = fetch_grader_response(db, notebook_id=query_body.notebook_id, user_email=user_email)
        #logging.debug(f"Fetched grader response: {grader_response}")
        if not grader_response:
            raise HTTPException(status_code=404, detail="No graded response found")

        return FetchGradedResponse(
            grader_response=grader_response
        )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during fetch_grader_response_api: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")

# Send email
def send_email(email_service, to, subject, body):
    message = MIMEText(body)
    message['to'] = to
    message['subject'] = subject
    raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
    
    try:
        sent = email_service.users().messages().send(
            userId='me',
            body={'raw': raw}
        ).execute()
        print(f"Email sent! Message ID: {sent['id']}")
        return sent
    except Exception as e:
        print(f"Error: {e}")
        return None


@app.post("/notify_student_grades", response_model=NotifyGradedResponse)
async def notify_student_grades_api(query_body: NotifyGradedRequest, request: Request):
    '''Fetch the graded response for a student from the database'''
    try:


        if not query_body.notebook_id:
            raise HTTPException(status_code=400, detail="notebook_id not provided")

        if not query_body.user_email:
            raise HTTPException(status_code=400, detail="user_email not provided")

        user_email = query_body.user_email

        grader_response = fetch_grader_response(db, notebook_id=query_body.notebook_id, user_email=user_email)
        #logging.debug(f"Fetched grader response: {grader_response}")
        if not grader_response:
            raise HTTPException(status_code=404, detail="No graded response found")

        user_name = grader_response.get('user_name', 'Student')
        total_marks = grader_response.get('total_marks', 0)
        max_marks = grader_response.get('max_marks', 0)
        subject = f"Graded Response for your submission {query_body.notebook_id}"
        msg_body = f"Hello {user_name},\n\n Your marks in {query_body.notebook_id} is {total_marks} out of {max_marks}. \n\nDetailed feedback for your submission"

        msg_body += json.dumps(grader_response, indent=4)

        msg_body+="\n\nBest regards,\nCP220-2025 Grading Assistant"
        
        logging.debug(f"Sending email to {user_email} with subject '{subject}' and body:\n{msg_body}")
        
        send_email(email_service, user_email, subject, msg_body)
    
        return NotifyGradedResponse(
            response=f"Sent email to {user_email} with graded response."
        )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during notify_student_grades_api: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")


@app.get("/profile")
async def profile(request: Request):
    # The middleware reads the cookie from the request and loads the session data.
    #print(request.session)
    user_id = request.session['user']['id']
    user_name = request.session['user']['name']
    if not user_id:
        return {"error": "Not logged in"}
    return {"user_id": user_id, "username": user_name}
    

@app.post("/fetch_student_list", response_model=FetchStudentListResponse)
async def fetch_student_list_api(query_body: FetchStudentListRequest, request: Request):
    '''
    Fetch the lst of  students from the database
    returns a dictionary of user_id to name and email  
    '''
    try:

        user_list = get_user_list(db)
        student_list = {}
        for user_id in user_list:
            userinfo_doc = db.collection(u'users').document(user_id).get()
            if userinfo_doc.exists:
                student_list[user_id]={'name': userinfo_doc.to_dict().get('name', 'Unknown'),'email': userinfo_doc.to_dict().get('email', 'Unknown')}
                if query_body.notebook_id is not None:
                    #check if the student has submitted the notebook
                    answer_doc = db.collection(u'users').document(user_id).collection(u'notebooks').document(query_body.notebook_id).get()
                    if answer_doc.exists:
                        student_list[user_id]['total_marks'] = answer_doc.to_dict().get('total_marks', 0.0)
                        student_list[user_id]['max_marks'] = answer_doc.to_dict().get('max_marks', 0.0)
                        student_list[user_id]['submitted'] = True
                    else:
                        student_list[user_id]['submitted'] = False
            else:
                logging.warning(f"User document for user_id {user_id} does not exist.")

        #logging.debug(f"Fetched student list: {user_list} of {type(user_list)}")

        return FetchStudentListResponse(
            response=student_list
        )

    except Exception as e:
        # By logging the exception with its traceback, you can see the root cause in your server logs.
        logging.error("An exception occurred during fetch_student_list_api: %s", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    #uvicorn.run(app, host="127.0.0.1", port=port)
    uvicorn.run(app, host="0.0.0.0", port=port) #allow access from any IP address