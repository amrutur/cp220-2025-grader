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
import uvicorn
from dotenv import load_dotenv
from pydantic import BaseModel, AnyUrl
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
                "https://8080-cs-763793587292-default.cs-asia-southeast1-fork.cloudshell.dev/callback"
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

#  This HTML includes JavaScript to handle the form submission.
#  This is being used  by the /ask endpoint to help test /query endpoint
#  by mimicing what would be sent from the google colab notebook
ask_form = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mimic inputs as if from the notebook cell for checking answer</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f4f4f9; }
        .container { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        h2 { text-align: center; color: #333; }
        form { display: flex; flex-direction: column; gap: 1rem; }
        label { font-weight: 500; color: #555; }
        input[type="text"] { padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; }
        input[type="text"]:focus { outline: none; border-color: #007bff; box-shadow: 0 0 0 2px rgba(0,123,255,0.25); }
        button { padding: 0.75rem; background-color: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; transition: background-color 0.2s; }
        button:hover { background-color: #0056b3; }
        #response-container { margin-top: 1.5rem; padding: 1rem; background-color: #e9ecef; border-radius: 4px; display: none; }
        pre { white-space: pre-wrap; word-wrap: break-word; }
    </style>
</head>
<body>
    <div class="container">
        <h2>Mimic inputs from notebook asnwer cell's check answer button</h2>
        <form id="ask-form">
            <div>
                <label for="input1">Question and  Answer:</label>
                <input type="text" id="input1" name="input1" placeholder="Question: question asked in the cell. Answer: answer provided by stdt" required>
            </div>
            <div>
                <label for="input2">Course No:</label>
                <input type="text" id="input2" name="input2" placeholder="Enter Course No" required>
            </div>
            <div>
                <label for="input3">Notebook name:</label>
                <input type="text" id="input3" name="input3" placeholder="Enter notebook name" required>
            </div>
           <div>
                <label for="input4">Question Id:</label>
                <input type="text" id="input4" name="input4" placeholder="Enter Question ID" required>
            </div>

            <div>
                <label for="input5">Rubric Link:</label>
                <input type="text" id="input5" name="input5" placeholder="Enter rubric file link (optional)">
            </div>

            <button type="submit">Check</button>
        </form>
        <div id="response-container">
            <strong>Response:</strong>
            <pre id="api-response"></pre>
        </div>
    </div>

    <script>
        document.getElementById('ask-form').addEventListener('submit', async function(event) {
            event.preventDefault(); // Stop the default page reload

            const formData = new FormData(this);
            const data = {
                query: formData.get('input1'),
                course_name: formData.get('input2'),
                notebook_name: formData.get('input3'),
                q_name: formData.get('input4'),
                rubric_link: formData.get('input5')
            };

            try {
                const response = await fetch('/query', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });

                if (!response.ok) {
                    throw new Error(`HTTP Error! query: ${data.query} course_name:${data.course_name} notebook_name: ${data.notebook_name} q_name:${data.q_name} Status: ${response.status}`);
                }

                const result = await response.json();

                // Display the response from the server
                const responseContainer = document.getElementById('response-container');
                const apiResponseElement = document.getElementById('api-response');
                apiResponseElement.textContent = JSON.stringify(result, null, 2);
                responseContainer.style.display = 'block';

            } catch (error) {
                console.error('Error:', error);
                document.getElementById('api-response').textContent = `Error: ${error.message}`;
                document.getElementById('response-container').style.display = 'block';
            }
        });
    </script>
</body>
</html>
"""



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
]

class QueryRequest(BaseModel):
    query: str
    course_name: str
    notebook_name: str
    q_name: str
    rubric_link: AnyUrl | None = None
 
class QueryResponse(BaseModel):
    response: str



def get_user_list(db):
    '''return the list of users in the firestore database'''
    users_ref = db.collection('users')
    docs = users_ref.select([]).stream()
    user_list  = []

    for doc in docs:
        user_list.append(doc.id)

    return user_list


app = FastAPI(title="CP220-2025 Agent API")

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
        if event.is_final_response():
            break
    return text

@app.post("/query", response_model=QueryResponse)
async def process_query(query_body: QueryRequest, request: Request):

   # print("Processing Query")
    runner = runner_assist

    if 'user' not in request.session:
        raise HTTPException(status_code=401, detail="User not authenticated. Please login first.")

    try:
        # Use a consistent session ID for the agent conversation
        session_id = request.session.get('agent_session_id', str(uuid.uuid4()))
        request.session['agent_session_id'] = session_id

        user_id = request.session['user']['id']
        user_name = request.session['user']['name']

        # Create a message from the query
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=query_body.query)]
        )

        print(f"User {user_name}, has asked for checking for question {query_body.q_name} in course {query_body.course_name} and notebook={query_body.notebook_name}")        

        if query_body.rubric_link:
            # Read rubric notebook using the application's service account, not the logged-in user's credentials.
            print(f"rubric link is {query_body.rubric_link}")
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
                print(json.dumps(notebook_json, indent=2))
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

@app.post("/grade", response_model=QueryResponse)
async def grade(query_body: QueryRequest, request: Request):
    '''Grade a single question in the notebook'''

    #print("Grading Question")
    
    runner= runner_score

    if 'user' not in request.session:
        raise HTTPException(status_code=401, detail="User not authenticated. Please login first.")

    try:
        # Use a consistent session ID for the agent conversation
        session_id = request.session.get('agent_session_id', str(uuid.uuid4()))
        request.session['agent_session_id'] = session_id

        user_id = request.session['user']['id']
        user_name = request.session['user']['name']

        # Create a message from the query
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=query_body.query)]
        )

        #print(f"User {user_name}, has asked for grading aquestion {query_body.q_name} in course {query_body.course_name} and notebook={query_body.notebook_name}")        

        if query_body.rubric_link:
            # Read rubric notebook using the application's service account, not the logged-in user's credentials.
            print(f"rubric link is {query_body.rubric_link}")
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
                print(json.dumps(notebook_json, indent=2))
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
    #print(request.session)
    user_id = request.session['user']['id']
    user_name = request.session['user']['name']
    if not user_id:
        return {"error": "Not logged in"}
    return {"user_id": user_id, "username": user_name}
    
@app.get("/ask", response_class=HTMLResponse)
async def ask(request:Request):
    ''' serves a simple form for testing access to agent, updation of database etc'''
    return HTMLResponse(content=ask_form, status_code=200)



if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    #uvicorn.run(app, host="127.0.0.1", port=port)
    uvicorn.run(app, host="0.0.0.0", port=port) #allow access from any IP address