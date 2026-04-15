Task 1 - CL.TE
Scenario
You are performing a security assessment on an internal e-commerce platform.
During traffic analysis, you intercept HTTP requests passing through a reverse proxy before reaching the backend server. The application uses persistent connections, and multiple requests are handled over the same connection.
While reviewing captured traffic, you notice inconsistencies in how request boundaries are handled between different components of the infrastructure.
Your task is to analyze the provided data and determine whether any unintended request has been processed by the backend system.

Access Instructions
Launch the lab environment:
HTTP-Request link

STEPS
Step 1 - Understand the Two Parsing Modes
Look at the request headers carefully. There are two headers that define how the body length should be calculated.
Identify which header is used by the proxy
Identify which header is used by the backend

Step 2 - Walk Through the Proxy’s Perspective
Follow how the proxy processes the request:
Determine how it calculates the body length
Count how much data it considers part of the request
From the proxy’s perspective, how many requests exist?

Step 3 - Walk Through the Backend’s Perspective
Now analyze how the backend interprets the same request:
Observe how it determines where the body ends
Identify the exact termination point
Compare this with the proxy’s interpretation

Step 4 - Identify Remaining Data
After the backend finishes processing the request:
Check if any data remains unprocessed
Determine how the backend handles this leftover data
Analyze whether it is treated as a separate request

Step 5 - Extract the Executed Request
From the remaining data:
Identify the method and endpoint
Extract the full path (including parameters)
This represents the unintended request processed by the backend

Objective
Analyze how the request is interpreted by different systems
Identify inconsistencies in request parsing
Determine the unintended request executed by the backend
Submit the correct answer to retrieve the flag

Submission
Enter your answer in the input field inside the lab
Click Submit Analysis
If correct, the flag will be revealed

Important Notes
Focus on request parsing behavior, not guessing
The answer is fully present in the provided data
Pay attention to how request boundaries are defined
No external tools are required

Flag Format
Flag{Scaler_XXXXXX}


















Task 2 - TE.CL Desync
Scenario
You are assessing a web application that utilizes caching mechanisms to improve performance for frequently accessed resources.
During your analysis, you observe that responses served to users are sometimes inconsistent and appear to contain unexpected data. This raises concerns about whether cached content can be influenced or manipulated under certain conditions.
Your task is to investigate how the application handles requests and determine whether it is possible to affect responses served to other users.

Access Instructions
Launch the lab environment using the link below:
HTTP Request Link

Steps
Step 1 - Identify Which Server Uses Which Header
This scenario involves a mismatch in how different systems interpret request boundaries.
Identify which component uses Transfer-Encoding
Identify which component uses Content-Length
Understand how this difference impacts request parsing

Step 2 - Follow the Proxy’s Parse
Analyze how the proxy processes the request:
Observe how chunked encoding is handled
Identify chunk sizes and termination points
Determine what the proxy considers as the complete request

Step 3 - Follow the Backend’s Parse
Now switch to the backend’s perspective:
Observe how it uses Content-Length
Determine how many bytes it reads as the request body
Compare this with the proxy’s interpretation

Step 4 - Identify the Remaining Data
After the backend processes its portion:
Check if additional data remains in the buffer
Analyze how this leftover data is interpreted
Determine whether it forms a new request

Step 5 - Determine the Executed Request
From the remaining data:
Identify the HTTP method
Extract the full path
This represents the request processed independently by the backend

Objective
Analyze inconsistencies in request parsing across systems
Understand how this affects caching and response handling
Identify the unintended request processed by the backend
Submit the correct answer to retrieve the flag

Submission
Enter your answer in the input field inside the lab
Click Submit Analysis
If correct, the flag will be displayed

Important Notes
Focus on how different systems interpret the same request
Pay attention to parsing boundaries and leftover data
This is a behavior and protocol-level analysis, not guessing
No external tools are required

Flag Format
Flag{Scaler_XXXXXX}










Task 3 - SSRF Chain
Scenario
You are assessing a cloud-hosted application that includes a webhook feature capable of fetching external URLs.
During routine monitoring, suspicious outbound requests are observed originating from the application. These requests appear to target internal resources and follow a structured pattern.
Additionally, cloud activity logs indicate that certain API calls were made using credentials that may not belong to legitimate users.
Your task is to analyze the available logs and determine how the attack progressed.

Access Instructions
Launch the lab environment using the link below:
HTTP Request Link

STEPS
Step 1 - Read the Application Logs Chronologically
Open the application logs panel.
Review the sequence of outbound requests
Focus on entries showing URL fetch activity
Identify how each request builds on the previous one

Step 2 - Identify the Target of the Initial Requests
Analyze the destination of these requests:
Look for repeated IP addresses or endpoints
Determine whether the target represents an internal or special-purpose service
Identify the common target across multiple requests

Step 3 - Understand the Enumeration Pattern
Observe how the attacker navigates through the target:
Initial request to a base path
Follow-up requests exploring deeper paths
Final request retrieving sensitive data

Step 4 - Correlate with Cloud Activity
Now examine the cloud activity logs:
Identify API calls made after the requests
Determine which identity or role was used
Analyze how access was expanded after obtaining credentials

Step 5 - Identify the Pivot Point
Determine the key element that enabled the attack:
Identify the endpoint that exposed sensitive metadata
This endpoint is common across all the requests
This is the entry point that made the entire chain possible

Objective
Analyze application logs and outbound requests
Understand how internal resources were accessed
Correlate SSRF activity with cloud-level impact
Identify the critical pivot point used in the attack
Submit the correct answer to retrieve the flag

Submission
Enter your answer in the input field inside the lab
Click Submit Analysis
If correct, the flag will be revealed

Important Notes
Focus on request patterns and log correlation
The attack is multi-step and builds progressively
Pay attention to repeated targets across requests
This is a chain-based analysis, not a single-step issue

Flag Format
Flag{Scaler_XXXXXX}
















TASK 4 - XSS Hijack
Scenario
You are investigating a potential client-side attack in a web application used by administrators to manage internal operations.
During analysis of stored data and access logs, you discover that a malicious payload was injected into user-controlled content. Shortly after, unusual outbound requests were observed from an administrator’s browser, followed by suspicious activity originating from a different IP address.
Your task is to analyze the available artifacts and determine how the attack was executed and where sensitive data was sent.

Access Instructions
Launch the lab environment using the link below:
HTTP Request

Steps
Step 1 - Trace the Injected Payload
Start by analyzing the stored application data:
Identify how the payload is executed
Locate any external resources being loaded
Note the URL where the external script is hosted

Step 2 - Analyze the External Script
Review the contents of the external script:
Determine what data is being collected
Observe how the data is processed or encoded
Identify how the script transmits the data

Step 3 - Differentiate Key Components
Distinguish between:
The location where the script is hosted
The destination where collected data is sent
These are separate endpoints and serve different purposes in the attack.

Step 4 - Validate with Network Activity
Examine the network capture:
Identify outbound requests triggered by the script
Observe the destination of these requests
Analyze any transmitted data

Step 5 - Correlate with Access Logs
Review the access logs:
Identify any session anomalies
Look for activity from unexpected IP addresses
Trace actions performed after the compromise

Objective
Analyze the injected payload and its execution flow
Understand how data is collected and transmitted
Identify the destination where sensitive data is exfiltrated
Submit the correct answer to retrieve the flag

Submission
Enter your answer in the input field inside the lab
Click Submit Analysis
If correct, the flag will be revealed

Important Notes
Focus on the difference between script hosting and data exfiltration
Pay attention to network behavior and request destinations
The attack involves multiple stages — analyze them sequentially
This is a client-side attack with server-side impact

Flag Format
Flag{Scaler_XXXXXX}

