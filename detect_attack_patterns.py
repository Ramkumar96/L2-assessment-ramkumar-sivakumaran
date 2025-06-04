import re
from collections import defaultdict

# File paths
logFilePath = "nginx_access.log"
outputFilePath = "results.txt"

# Configuration thresholds
maxRequestsPerIp = 5
maxErrorsPerIp = 3
loginRequestThreshold = 3

# Regex pattern to extract log components
logPattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+\w+\s+\[(?P<timestamp>[^\]]+)\]\s+"[^"]+"\s+"(?P<method>\w+)\s(?P<url>\S+).*?"\s(?P<status>\d{3})\s'
)

ipRequestCount = defaultdict(int)
ipErrorCount = defaultdict(int)
ipLoginAttempts = defaultdict(int)

# Read from log file or string
with open(logFilePath, "r") as file:
    for line in file:
        match = logPattern.search(line)
        if match:
            ip = match.group("ip")
            status = int(match.group("status"))
            url = match.group("url")

            ipRequestCount[ip] += 1

            if status >= 400:
                ipErrorCount[ip] += 1

            if "/login" in url:
                ipLoginAttempts[ip] += 1

# Write analysis results to results.txt
with open("results.txt", "w") as outputFile:
    outputFile.write("\n--- Task 03 : Attack Pattern Detection Report ---\n\n")

    # Frequent Requesters
    outputFile.write("\nHigh Request Rate IPs:\n")
    for ip, count in ipRequestCount.items():
        if count > maxRequestsPerIp:
            outputFile.write(f"  - {ip} made {count} requests\n ")

    # Error-prone IPs
    outputFile.write("\n\n  High Error Rate IPs:\n")
    for ip, count in ipErrorCount.items():
        if count > maxErrorsPerIp:
            outputFile.write(f"  - {ip} caused {count} errors (4xx/5xx)\n ")

    # Brute-force login attempts
    outputFile.write("\n\n  Potential Brute-force Login IPs:\n")
    for ip, count in ipLoginAttempts.items():
        if count > loginRequestThreshold:
            outputFile.write(f"  - {ip} attempted to access /login {count} times\n ")

    outputFile.write("\n--- End of Task 03 Report ---")