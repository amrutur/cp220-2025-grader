#api_server.py
#modified from : https://saptak.in with lots of help from gemini !
import os
import asyncio
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
from google.auth.transport.requests import Request as GoogleAuthRequest
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build

from google.genai import types
from google.cloud import secretmanager

import firebase_admin
from firebase_admin import credentials, firestore



# Allow insecure transport for local development (OAUTHLIB requirement).
if (int(os.environ.get('PRODUCTION'))==0):
    #print("using insecure oauth tranport for development testing")
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


# Import your agents
import agent  # Update with your actual imports

#    This HTML includes JavaScript to handle the form submission.

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
                    throw new Error(`HTTP error! Status: ${response.status}`);
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
if os.environ.get('PRODUCTION')==1 :
    REDIRECT_URI_INDEX = 1 #production deployment
else:
    REDIRECT_URI_INDEX = 2 # testing in local server
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

print(f"project_id is {project_id}")


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

def get_user_list(db):
    '''return the list of users in the firestore database'''
    users_ref = db.collection('users')
    docs = users_ref.select([]).stream()
    user_list  = []

    for doc in docs:
        user_list.append(doc.id)

    return user_list

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

import io
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload
import json

def get_notebook_content_from_link(creds_dict: dict, file_id: str):
    """
    Downloads content of a google colab notebook from a given file_id.

    Args:
        creds_dict: A dictionary of the user's OAuth credentials.
        file_id : file_id of the notebook

    Returns:
        The content of the notebook as a string, or None if not found.
    """
    try:
        credentials = Credentials(**creds_dict)
        drive_service = build('drive', 'v3', credentials=credentials)

        # Download the file content
        request = drive_service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
            # You can add progress reporting here if needed
            # print(f"Download {int(status.progress() * 100)}%.")

        # The content is in fh; decode it as UTF-8
        notebook_content = fh.getvalue().decode('utf-8')
        return notebook_content

    except Exception as e:
        # In a production app, you'd want more specific error handling
        print(f"An error occurred while accessing Google Drive: {e}")
        return None

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

        # Find the index of 'd' which usually precedes the file ID
        d_index = parts.index('d')
        
        # The file ID is usually the next part after 'd'
        file_id = parts[d_index + 1]

        return file_id
    except ValueError:
        print("Invalid share link format.")
        return None
    except IndexError:
        print("Could not extract file ID from the share link.")
        return None

def load_notebook_from_google_drive(creds_dict: dict, share_link: str):
    """
    Loads a Colab notebook from Google Drive given its share link.

    Args:
        creds_dict: A dictionary containing the user's Google API credentials.
        share_link: The shareable link to the Colab notebook on Google Drive.

    Returns:
        The content of the notebook as a string, or None if the notebook
        cannot be loaded.
    """
    file_id = get_file_id_from_share_link(share_link)

    if not file_id:
        print("Could not extract file ID from share link.")
        return None

    notebook_content = get_notebook_content_from_link(creds_dict, file_id)
    return notebook_content

#Example usage:
# Assuming you have obtained the creds_dict and share_link
# notebook_content = load_notebook_from_google_drive(creds_dict, share_link)

# if notebook_content:
#   print("Notebook content loaded successfully.")
#   # Process the notebook content as needed
# else:
#   print("Failed to load notebook content.")



from google.oauth2.credentials import Credentials
import io
from googleapiclient.http import MediaIoBaseDownload

def get_folder_id_by_path(drive_service, path: str) -> str | None:
    """
    Finds the ID of a folder given its full path from 'My Drive'.

    Args:
        drive_service: The authenticated Google Drive service client.
        path: The folder path, e.g., "Colab Notebooks/CP220-2025/Answers".

    Returns:
        The folder ID as a string, or None if the path is not found.
    """
    parent_id = 'root'  # Start from the root of "My Drive"
    found_path_parts = []
    # Sanitize path by removing leading/trailing slashes and splitting
    folders = [folder for folder in path.strip('/').split('/') if folder]

    for folder_name in folders:
        current_search_path = "My Drive/" + "/".join(found_path_parts)
        # Note: A more robust implementation might escape special characters in folder_name.
        query = (
            f"name = '{folder_name}' and "
            f"mimeType = 'application/vnd.google-apps.folder' and "
            f"'{parent_id}' in parents and "
            f"trashed = false"
        )

        try:
            results = drive_service.files().list(
                q=query,
                spaces='drive',
                fields='files(id, name)',
                pageSize=1
            ).execute()
        except Exception as e:
            print(f"Error querying for folder '{folder_name}': {e}")
            return None

        items = results.get('files', [])
        if not items:
            print(f"Folder '{folder_name}' not found in the path: '{current_search_path}'")
            return None

        parent_id = items[0]['id']  # This becomes the parent for the next iteration
        found_path_parts.append(folder_name)

    return parent_id

def get_notebook_from_drive(creds_dict: dict, notebook_name: str, folder_path: str | None = None):
    """
    Accesses Google Drive to find and download a .ipynb notebook.

    Args:
        creds_dict: A dictionary of the user's OAuth credentials.
        notebook_name: The name of the notebook to find (e.g., "MyNotebook.ipynb").
        folder_path: Optional. The path to the folder containing the notebook, e.g., "Colab Notebooks/CP220-2025".

    Returns:
        The content of the notebook as a string, or None if not found.
    """
    try:
        credentials = Credentials(**creds_dict)
        drive_service = build('drive', 'v3', credentials=credentials)

        parent_folder_id = None
        if folder_path:
            parent_folder_id = get_folder_id_by_path(drive_service, folder_path)
            if not parent_folder_id:
                print(f"The specified folder path was not found: {folder_path}")
                return None

        # Build the search query
        query_parts = [
            f"name = '{notebook_name}'",
            "trashed = false"
            # You could also add: "and mimeType = 'application/vnd.google.colaboratory'"
        ]
        if parent_folder_id:
            query_parts.append(f"'{parent_folder_id}' in parents")

        query = " and ".join(query_parts)

        print(f"query={query}, parent_folder_id={parent_folder_id}")
        results = drive_service.files().list(
            q=query,
            spaces='drive',
            fields='files(id, name)',
            pageSize=1  # We only need the first match
        ).execute()
        items = results.get('files', [])

                

        if not items:
            location = f"in folder '{folder_path}'" if folder_path else "in your Google Drive"
            print(f"No notebook named '{notebook_name}' found {location}.")
            return None

        file_id = items[0]['id']
        print(f"Found notebook '{items[0]['name']}' with ID: {file_id}")

        # Download the file content
        request = drive_service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()
            # You can add progress reporting here if needed
            # print(f"Download {int(status.progress() * 100)}%.")

        # The content is in fh; decode it as UTF-8
        notebook_content = fh.getvalue().decode('utf-8')
        return notebook_content

    except Exception as e:
        # In a production app, you'd want more specific error handling
        print(f"An error occurred while accessing Google Drive: {e}")
        return None


@app.get("/notebook/{notebook_name}", tags=["Google Drive"])
async def read_notebook(notebook_name: str, request: Request, path: str | None = None):
    """
    An endpoint to retrieve a notebook from the logged-in user's Google Drive.
    Optionally, specify the folder path as a query parameter.
    e.g., /notebook/MyNotebook.ipynb?path=Colab+Notebooks/CP220-2025
    """
    if 'credentials' not in request.session:
        raise HTTPException(status_code=401, detail="User not authenticated. Please login first.")

    creds_dict = request.session['credentials']

    # Basic security checks
    if "/" in notebook_name or ".." in notebook_name:
        raise HTTPException(status_code=400, detail="Invalid notebook name.")
    if path and (".." in path):
        raise HTTPException(status_code=400, detail="Invalid folder path.")

    # Run the blocking Google Drive API call in a separate thread
    notebook_content = await asyncio.to_thread(get_notebook_from_drive, creds_dict, notebook_name, path)

    if notebook_content is None:
        location_detail = f"in folder '{path}'" if path else "anywhere"
        raise HTTPException(
            status_code=404, detail=f"Notebook '{notebook_name}' not found {location_detail} in your Google Drive."
        )

    try:
        # .ipynb files are JSON, so we can return them as JSON
        notebook_json = json.loads(notebook_content)
        return JSONResponse(content=notebook_json)
    except json.JSONDecodeError:
        # Or return as plain text if it's not valid JSON for some reason
        return HTMLResponse(content=f"<pre>Could not parse notebook as JSON. Raw content:\n\n{notebook_content}</pre>")



@app.post("/check", response_model=QueryResponse)
async def do_check(query_body: QueryRequest, request: Request):
    try:
        if 'user' not in request.session:
            raise HTTPException(status_code=401, detail="User not authenticated")

        user_id = request.session['user']['id']
        user_name = request.session['user']['name']

        # Create a message from the query
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=query_body.query)]
        )

        return QueryResponse(response="Check Ok")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

async def run_agent_and_get_response(current_session_id: str, user_id: str, content: types.Content) -> str:
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
        print(f"rubric link is {query_body.rubric_link}")

        try:
            # Attempt to get the response using the current session ID
            response_text = await run_agent_and_get_response(session_id,user_id, content)
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
                response_text = await run_agent_and_get_response(new_session_id, user_id, content)
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
        import logging
        import traceback
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