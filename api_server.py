# api_server.py
#modified from : https://saptak.in
import os
import asyncio
import json
import uuid
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
import uvicorn
from dotenv import load_dotenv

from google.adk import Runner
from google.adk.sessions import DatabaseSessionService, Session

from google.genai import types 


# Import your agents
import agent  # Update with your actual imports

# Define or import root_agent
root_agent = agent.root_agent  # Update this line if your agent module uses a different name or structure

# Load environment variables
load_dotenv()

app = FastAPI(title="CP220-2025 Agent API")

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

class QueryRequest(BaseModel):
    query: str
    user_id: str = "default_user"
    session_id: str = None

class QueryResponse(BaseModel):
    response: str
    session_id: str

@app.post("/check", response_model=QueryResponse)
async def check(request: QueryRequest):
    try:

        # Get or create session ID
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
            
        content = types.Content(
            role="user",
            parts=[types.Part.from_text(text=request.query)]
        )
        #print(f"request.query: {request.query}, query part: {types.Part.from_text(text="hello")}, request.user_id: {request.user_id}, request.session_id: {request.session_id}")
        
        return QueryResponse(
            response="Session check successful.",
            session_id=session_id
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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

@app.get("/",tags=["Health Check"])
async def root():
    return {"message": "cp220-2025-grader API has come to work!"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    #uvicorn.run(app, host="127.0.0.1", port=port)
    uvicorn.run(app, host="0.0.0.0", port=port) #allow access from any IP address