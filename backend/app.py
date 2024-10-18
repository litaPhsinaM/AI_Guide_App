from flask import Flask, request, jsonify
from openai import OpenAI
from dotenv import load_dotenv
import os
import time  # Import time for measuring response time

# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)

# Create an OpenAI client
client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))

@app.route('/ask', methods=['POST'])
def ask_question():
    start_time = time.time()  # Start timer to measure response time

    # Get the user question and model from the request
    data = request.get_json()
    question = data.get('question')
    model = data.get('model', 'gpt-4')  # Default to GPT-4 if no model is provided

    # Call OpenAI's ChatCompletion API
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": question}
            ],
            max_tokens=50  # Adjust as needed for shorter responses
        )
        answer = response.choices[0].message.content.strip()

        end_time = time.time()  # End timer
        elapsed_time = end_time - start_time  # Calculate response time
        print(f"Response time: {elapsed_time} seconds")  # Log the time taken

        # Return the answer along with the response time
        return jsonify(answer=answer, response_time=f"{elapsed_time} seconds")

    except Exception as e:
        return jsonify(error=str(e)), 500

if __name__ == '__main__':
    app.run(debug=True)