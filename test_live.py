import os
import httpx

# Retrieve the API key from environment variable, or replace 'YOUR_OPENAI_API_KEY' with your real key
api_key = os.getenv("OPENAI_API_KEY", "YOUR_OPENAI_API_KEY")

proxy_url = "http://localhost:8080/v1/chat/completions"

headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

payload = {
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "What is the capital of France?"}],
    "stream": True
}

if api_key == "YOUR_OPENAI_API_KEY":
    print("WARNING: Please set the OPENAI_API_KEY environment variable or edit the key in this script.")

print(f"Using API key prefix: {api_key[:10]}...")
print("Sending streaming request through the GuardRail Reverse Proxy...")
try:
    with httpx.stream("POST", proxy_url, json=payload, headers=headers, timeout=60.0) as response:
        print(f"Response Status Code: {response.status_code}")
        for line in response.iter_lines():
            if line.strip():
                print(line)
except Exception as e:
    print(f"An error occurred: {e}")
