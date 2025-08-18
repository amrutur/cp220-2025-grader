ask_form = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Check Answer Form</title>
    <!-- Tailwind CSS for styling -->
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap">
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }
    </style>
</head>
<body class="bg-gray-100 flex items-center justify-center min-h-screen">
    <div class="w-full max-w-md p-8 space-y-6 bg-white rounded-xl shadow-lg">
        <h2 class="text-2xl font-bold text-center text-gray-800">Check Your Answer</h2>
        
        <!-- The Form -->
        <form id="check-form" class="space-y-4">
            <!-- Text Box 1 -->
            <div>
                <label for="input1" class="block text-sm font-medium text-gray-700">Query</label>
                <input type="text" id="input1" name="input1"
                       class="w-full px-3 py-2 mt-1 text-gray-700 bg-gray-50 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                       placeholder="Enter a text string like this: The question asked is: <question>. The student's answer is: <answer>">
            </div>

            <!-- Text Box 2 -->
            <div>
                <label for="input2" class="block text-sm font-medium text-gray-700">Question Number</label>
                <input type="int" id="input2" name="input2"
                       class="w-full px-3 py-2 mt-1 text-gray-700 bg-gray-50 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                       placeholder="Enter the question number">
            </div>

            <!-- Text Box 3 -->
            <div>
                <label for="input3" class="block text-sm font-medium text-gray-700">Course Number</label>
                <input type="text" id="input3" name="input3"
                       class="w-full px-3 py-2 mt-1 text-gray-700 bg-gray-50 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                       placeholder="enter the course number (default: cp220-2025)">
            </div>

            <!-- Submit Button -->
            <div>
                <button type="submit"
                        class="w-full px-4 py-2 font-semibold text-white bg-blue-600 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 transition-colors duration-300">
                    ask
                </button>
            </div>
        </form>

        <!-- Div to display the API response for testing -->
        <div id="response-container" class="mt-6 p-4 bg-gray-50 rounded-md border border-gray-200 text-sm text-gray-600 hidden">
            <h3 class="font-semibold text-gray-800 mb-2">API Response:</h3>
            <pre id="api-response" class="whitespace-pre-wrap break-all"></pre>
        </div>
    </div>

    <script>
        // Get the form element
        const form = document.getElementById('check-form');
        const responseContainer = document.getElementById('response-container');
        const apiResponseElement = document.getElementById('api-response');

        // Add an event listener for the form's submit event
        form.addEventListener('submit', async function(event) {
            // Prevent the default form submission behavior (which reloads the page)
            event.preventDefault();

            // 1. Gather the data from the text boxes
            const formData = new FormData(form);
            const data = {
                query: formData.get('input1'),
                qnum: formData.get('input2'),
                coursenum: formData.get('input3')
            };

            // 2. Send the API request to the /check endpoint
            try {
                // We use the 'fetch' API to make a POST request
                const response = await fetch('/check', {
                    method: 'POST',
                    headers: {
                        // Tell the server we're sending JSON data
                        'Content-Type': 'application/json'
                    },
                    // Convert the JavaScript object to a JSON string
                    body: JSON.stringify(data)
                });

                // Check if the request was successful
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }

                // Parse the JSON response from the server
                const result = await response.json();
                
                // 3. Display the response for testing
                apiResponseElement.textContent = JSON.stringify(result, null, 2);
                responseContainer.classList.remove('hidden');

            } catch (error) {
                // Handle any errors that occurred during the fetch
                apiResponseElement.textContent = `Error: ${error.message}\n\nNote: This is a frontend-only example. The '/check' endpoint needs to be implemented in your backend server.`;
                responseContainer.classList.remove('hidden');
                console.error('There was a problem with the fetch operation:', error);
            }
        });
    </script>
</body>
</html>
'''

ask_form2 = """
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