import re
from collections import Counter

# File paths
logFilePath = "nginx_access.log"
outputFilePath = "log_analysis.txt"

# Compile regex pattern to extract relevant fields from log lines
logPattern = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+-\s+BYPASS\s+\[.*?\]\s+".*?"\s+"(?P<method>\w+)\s+[^"]+"\s+(?P<status>\d{3})\s+(?P<bytesSent>\d+)'
)

# Initialize counters and accumulators
ipRequestCount = Counter()
totalRequestCount = 0
failedRequestCount = 0
getRequestByteTotal = 0
getRequestCount = 0

# Process each line in the log file
with open(logFilePath, 'r') as logFile:
    for line in logFile:
        match = logPattern.search(line)
        if match:
            ip = match.group('ip')
            method = match.group('method')
            status = int(match.group('status'))
            bytesSent = int(match.group('bytesSent'))

            # Count requests per IP
            ipRequestCount[ip] += 1
            totalRequestCount += 1

            # Count failed requests (status code 400–599)
            if 400 <= status <= 599:
                failedRequestCount += 1

            # Accumulate data for GET requests
            if method == 'GET':
                getRequestByteTotal += bytesSent
                getRequestCount += 1

# Write analysis results to output file
with open(outputFilePath, "w") as outputFile:
    outputFile.write("Task 1: Nginx Log Analysis Report \n\n")

    # Top 5 IPs by request count
    outputFile.write("Top 5 IP addresses by request count:\n\n")
    for ip, count in ipRequestCount.most_common(5):
        outputFile.write(f"{ip} : {count} requests\n")

    outputFile.write("\n")

    # Percentage of failed requests
    if totalRequestCount:
        failedPercentage = (failedRequestCount / totalRequestCount) * 100
    else:
        failedPercentage = 0
    outputFile.write(f"Percentage of requests with status in the 400–599 range : {failedPercentage:.2f}%\n\n")
    
    outputFile.write("\n")
    
    # Average response size for GET requests
    if getRequestCount:
        avgGetResponseSize = getRequestByteTotal / getRequestCount
    else:
        avgGetResponseSize = 0   
    outputFile.write(f"Average response size in bytes for GET requests : {avgGetResponseSize:.2f} bytes\n")


outputFile.write("\n--- End of Task 01 Report ---")