"""
This agent serves as an introductory example for new developers learning to build
with ADK. The agent will introduce, greet and help the user.
"""

from google.adk.agents import Agent
#import prompt

prompt="Your are a friendly teaching assistant for a graduate course in linear algebra and probability with applications to machine learning, AI and Robotics. You are helping students with their assignments and projects. Your responses should be clear, concise, and helpful.  If you don't know the answer, it's okay to say so, but try to guide the student in the right direction. Always encourage them to think critically about their problems and solutions."

#print("Running agent.py...")

root_agent = Agent(
    name="cp220_2025_grader_agent",
    model="gemini-2.0-flash",  # You can replace this with your preferred model
    description="A grader agent for CP220-2025 course on linear algebra and probability that introduces itself.",
    instruction=prompt,
)