"""
LangChain ReAct Agent for Network Intrusion Detection.
Uses Groq (Llama) as the LLM and custom ML-based tools.
"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage

from agent.tools import ALL_TOOLS
from agent.models_loader import models

# Load environment variables
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env", override=True)

SYSTEM_PROMPT = """You are CyberGuard Agent, an expert Network Security Analyst AI.

You monitor network traffic, detect intrusions, block attackers, and alert the security team.

## Your Tools:

1. **analyze_flow** - Analyze a network flow using 3-stage ML pipeline (Anomaly + Binary + Attack Classification). If malicious, an alert is auto-created.
2. **generate_random_flow** - Get a random real flow sample for testing.
3. **get_flow_statistics** - Calculate traffic statistics and spot anomalies.
4. **explain_prediction** - Explain why the model flagged traffic.
5. **get_attack_info** - Get info about attack types (DoS, Exploits, Backdoor, etc.)
6. **block_ip** - Block a malicious IP address.
7. **unblock_ip** - Remove an IP from the block list.
8. **get_blocked_ips_list** - View all currently blocked IPs.
9. **get_alerts_list** - View all security alerts.

## Behavior Rules:

- When you detect malicious traffic, ALWAYS recommend blocking the source IP.
- If the user agrees or says to block, use the block_ip tool immediately.
- Present results clearly with severity levels.
- If the user speaks Arabic, respond in Arabic. If English, respond in English.
- When asked to test or demo, use generate_random_flow then analyze_flow.
- For high packet counts or byte counts in short duration, flag as suspicious.
- Always provide actionable security recommendations.

## Severity Levels:
- CRITICAL: Probability > 0.85, active exploitation
- HIGH: Probability > 0.5, confirmed malicious
- MEDIUM: Anomaly detected but classifier uncertain
- LOW: Statistical anomaly only
"""


def create_agent(temperature: float = 0.1):
    """Create and return the LangChain agent with all tools."""
    models.load()

    llm = ChatGroq(
        model="llama-3.1-8b-instant",
        temperature=temperature,
        groq_api_key=os.getenv("GROQ_API_KEY"),
    )

    agent = create_react_agent(llm, tools=ALL_TOOLS, prompt=SYSTEM_PROMPT)

    class DummyAction:
        def __init__(self, tool_name, tool_input):
            self.tool = tool_name
            self.tool_input = tool_input

    class LegacyAgentWrapper:
        def __init__(self, core_agent):
            self.agent = core_agent
        
        def invoke(self, inputs):
            try:
                chat_history = inputs.get("chat_history", [])
                actual_input = inputs.get("input", "")
                messages = chat_history + [HumanMessage(content=actual_input)]
                
                result = self.agent.invoke({"messages": messages})
                
                final_message = result["messages"][-1]
                intermediate_steps = []
                
                for i, msg in enumerate(result["messages"]):
                    try:
                        if msg.type == "ai" and getattr(msg, "tool_calls", None):
                            for tool_call in msg.tool_calls:
                                tool_output = ""
                                for next_msg in result["messages"][i+1:]:
                                    if next_msg.type == "tool" and getattr(next_msg, "tool_call_id", None) == tool_call.get("id"):
                                        tool_output = next_msg.content
                                        break
                                
                                action = DummyAction(tool_call.get("name", "unknown"), tool_call.get("args", {}))
                                intermediate_steps.append((action, tool_output))
                    except Exception as step_err:
                        print(f"[!] Step extraction error: {step_err}")
                        continue

                return {
                    "output": final_message.content,
                    "intermediate_steps": intermediate_steps
                }
            except Exception as e:
                import traceback
                traceback.print_exc()
                return {
                    "output": f"Agent execution error: {str(e)}",
                    "intermediate_steps": []
                }

    return LegacyAgentWrapper(agent)
