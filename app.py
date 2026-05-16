import os
import sys

# Add src to the path so imports work correctly
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))

# Import and run the streamlit app
# Note: In Hugging Face, we can also point the Space to src/agent_app.py directly,
# but having a root app.py is more standard for simple deployments.

if __name__ == "__main__":
    import subprocess
    # Run the streamlit application
    # We use subprocess to call streamlit because it handles the environment and port correctly on HF
    try:
        subprocess.run(["streamlit", "run", "src/agent_app.py", "--server.port", "7860", "--server.address", "0.0.0.0"])
    except Exception as e:
        print(f"Error launching application: {e}")
