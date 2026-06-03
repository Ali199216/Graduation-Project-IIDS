"""
LangChain ReAct Agent for Network Intrusion Detection.
Uses Groq (Llama) as the LLM and custom ML-based tools with smart query routing.
"""
import os
import sys
import re
from pathlib import Path
from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langchain_groq import ChatGroq
from langgraph.prebuilt import create_react_agent
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage

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

def route_query(text: str) -> str:
    """Route query to: 'greeting', 'info', or 'action' to optimize speed and prevent tool errors."""
    t = text.lower().strip()
    
    # Greetings & chit-chat keywords
    greetings = [
        "hi", "hello", "hey", "good morning", "good evening", "howdy", "welcome",
        "how are you", "who are you", "what is your name", "thank you", "thanks", "bye", "goodbye",
        "مرحبا", "أهلاً", "اهلين", "السلام عليكم", "صباح الخير", "مساء الخير", "كيف حالك", "مين انت", 
        "من أنت", "اسمك ايه", "بتعمل ايه", "شكرا", "مع السلامة", "شات بوت", "الجو", "دردشة"
    ]
    if any(g in t for g in greetings) or len(t.split()) <= 2:
        # Ensure it's not a short action command
        has_action_indicators = any(x in t for x in ["block", "alert", "flow", "حظر", "تنبيه", "فك", "ip"])
        if not has_action_indicators:
            return "greeting"

    # Action keywords that require database query or pipeline execution
    actions = [
        "block", "unblock", "analyze", "test", "generate", "predict", "explain prediction",
        "show blocked", "list blocked", "get blocked", "show alerts", "list alerts", "get alerts",
        "حظر", "فك الحظر", "تحليل", "فحص", "اختبار", "توليد", "عرض المحظورين", "الأيبيهات المحظورة",
        "عرض التنبيهات", "التنبيهات النشطة", "ليست", "قائمة", "اي بي", "ip"
    ]
    if any(a in t for a in actions):
        return "action"
        
    # Default is informational security query
    return "info"

def create_agent(temperature: float = 0.1):
    """Create and return the LangChain agent with all tools and fallback support."""
    models.load()

    groq_api_key = os.getenv("GROQ_API_KEY")

    # Primary LLM: 70B for detailed reasoning & accurate tool calls
    try:
        llm_70b = ChatGroq(
            model="llama-3.3-70b-versatile",
            temperature=temperature,
            groq_api_key=groq_api_key,
        )
        agent_70b = create_react_agent(llm_70b, tools=ALL_TOOLS, prompt=SYSTEM_PROMPT)
    except Exception as e:
        print(f"[!] Error creating 70B agent: {e}")
        llm_70b = None
        agent_70b = None

    # Fast Fallback LLM: 8B for fast greetings and backup in case 70B fails
    try:
        llm_8b = ChatGroq(
            model="llama-3.1-8b-instant",
            temperature=temperature,
            groq_api_key=groq_api_key,
        )
        agent_8b = create_react_agent(llm_8b, tools=ALL_TOOLS, prompt=SYSTEM_PROMPT)
    except Exception as e:
        print(f"[!] Error creating 8B agent: {e}")
        llm_8b = None
        agent_8b = None

    class DummyAction:
        def __init__(self, tool_name, tool_input):
            self.tool = tool_name
            self.tool_input = tool_input

    class LegacyAgentWrapper:
        def __init__(self, agent_70b, agent_8b, llm_70b, llm_8b):
            self.agent_70b = agent_70b
            self.agent_8b = agent_8b
            self.llm_70b = llm_70b
            self.llm_8b = llm_8b
        
        def invoke(self, inputs):
            chat_history = inputs.get("chat_history", [])
            actual_input = inputs.get("input", "")
            
            # Determine route
            route = route_query(actual_input)
            
            # 1. GREETING ROUTE (Instant 8B Response)
            if route == "greeting" and self.llm_8b is not None:
                try:
                    messages = [
                        SystemMessage(content="You are CyberGuard Agent, a friendly network security assistant. Respond to the user's greeting or simple message politely, directly, and in the same language they used (Arabic or English). Keep your answer concise and friendly."),
                    ]
                    for msg in chat_history[-2:]:
                        messages.append(msg)
                    messages.append(HumanMessage(content=actual_input))
                    
                    response = self.llm_8b.invoke(messages)
                    return {
                        "output": response.content,
                        "intermediate_steps": []
                    }
                except Exception as e:
                    print(f"[!] Greeting route failed: {e}")

            # 2. INFO ROUTE (Fast 70B Direct Response, no tools overhead)
            if route == "info" and self.llm_70b is not None:
                try:
                    messages = [
                        SystemMessage(content="You are CyberGuard Agent, an expert Network Security Analyst. Answer the user's query professionally, accurately, and in detail without calling any tools. Respond in the same language they used (Arabic or English). If they ask about attacks, explain the common types (DoS, Exploits, Backdoor, Fuzzers, Reconnaissance, Worms, Shellcode)."),
                    ]
                    for msg in chat_history[-2:]:
                        messages.append(msg)
                    messages.append(HumanMessage(content=actual_input))
                    
                    response = self.llm_70b.invoke(messages)
                    return {
                        "output": response.content,
                        "intermediate_steps": []
                    }
                except Exception as e:
                    print(f"[!] Info route 70B failed: {e}")
                    # Fallback to 8B direct response
                    if self.llm_8b is not None:
                        try:
                            response = self.llm_8b.invoke(messages)
                            return {
                                "output": response.content,
                                "intermediate_steps": []
                            }
                        except Exception:
                            pass

            # 3. ACTION ROUTE (Run ReAct Agent with tools)
            # Truncate chat history to avoid Groq TPM limits
            if len(chat_history) > 2:
                chat_history = chat_history[-2:]
            messages = chat_history + [HumanMessage(content=actual_input)]

            # Try primary 70B agent
            if self.agent_70b is not None:
                try:
                    result = self.agent_70b.invoke({"messages": messages})
                    return self._format_result(result)
                except Exception as e:
                    print(f"[!] 70B Agent action failed: {e}. Trying 8B agent fallback...")

            # Try fallback 8B agent
            if self.agent_8b is not None:
                try:
                    result = self.agent_8b.invoke({"messages": messages})
                    return self._format_result(result)
                except Exception as e:
                    print(f"[!] 8B Agent action failed: {e}. Trying direct response...")

            # Direct fallback if agent execution completely fails
            if self.llm_8b is not None:
                try:
                    response = self.llm_8b.invoke([
                        SystemMessage(content="You are CyberGuard Agent. Respond to the user's request as best as you can in the same language. Note: tool execution failed, so answer using your general knowledge."),
                        HumanMessage(content=actual_input)
                    ])
                    return {
                        "output": response.content,
                        "intermediate_steps": []
                    }
                except Exception as e:
                    print(f"[!] All LLM fallbacks failed: {e}")

            # Offline Emergency Response
            is_arabic = any(char in actual_input for char in "أبتثجحخدذرزسشصضطظعغفقكلمنهوي")
            if is_arabic:
                offline_msg = "أنا عميل CyberGuard، مساعد أمن الشبكات الذكي الخاص بك. أواجه حالياً صعوبة في الاتصال بالخادم السحابي، ولكن يمكنك استخدام أدوات لوحة التحكم لتحليل البيانات أو حظر الأيبيهات يدوياً."
            else:
                offline_msg = "I am CyberGuard Agent, your intelligent Network Security Analyst. I am currently experiencing connection difficulties with the cloud server, but you can still use the dashboard controls to analyze traffic or block IPs manually."
            
            return {
                "output": offline_msg,
                "intermediate_steps": []
            }

        def _format_result(self, result):
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

    return LegacyAgentWrapper(agent_70b, agent_8b, llm_70b, llm_8b)
