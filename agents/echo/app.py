# app.py
from microsoft_agents.hosting.core import AgentApplication, MemoryStorage
from microsoft_agents.activity import ActivityTypes, MessageFactory

class EchoAgent(AgentApplication):
    def __init__(self):
        super().__init__(storage=MemoryStorage())
        # register handler for message activities
        @self.on_activity(ActivityTypes.MESSAGE)
        async def on_message(turn_context, turn_state, cancellation_token=None):
            text = turn_context.activity.text
            # send back the user’s message prefixed with 'Echo:'
            await turn_context.send_activity(
                MessageFactory.text(f"Echo: {text}")
            )

# Optionally define authentication configuration for testing
from microsoft_agents.hosting.core import AgentAuthConfiguration
from start_server import start_server

def main():
    agent = EchoAgent()
    # Use a default no‑auth config for local testing
    auth_config = AgentAuthConfiguration(acquire_tokens_for_author={},
                                         allow_anonymous_requests=True)
    # Start the HTTP server on http://localhost:3978/api/messages
    start_server(agent, auth_config)

if __name__ == "__main__":
    main()