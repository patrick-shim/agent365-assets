# app.py
import re

from microsoft_agents.hosting.core import AgentApplication, MemoryStorage
from microsoft_agents.activity import Activity

class EchoAgent(AgentApplication):
    def __init__(self):
        super().__init__(storage=MemoryStorage())
        # register handler for message activities
        @self.message(re.compile(r".*"))
        async def on_message(turn_context, turn_state, cancellation_token=None):

            text = turn_context.activity.text
            # send back the user’s message prefixed with 'Echo:'
            await turn_context.send_activity(
                Activity(type="message", text=f"Echo: {text}")
            )

# Optionally define authentication configuration for testing
from microsoft_agents.hosting.core import AgentAuthConfiguration
from start_server import start_server

def main():
    agent = EchoAgent()
    # Use a default no‑auth config for local testing
    auth_config = AgentAuthConfiguration(anonymous_allowed=True)
    # Start the HTTP server on http://localhost:3978/api/messages
    start_server(agent, auth_config)

if __name__ == "__main__":
    main()