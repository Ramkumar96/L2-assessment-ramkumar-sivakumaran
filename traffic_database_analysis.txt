-- Query to Find Hour of the day with the highest average response time
-- Query Results : 22 Hour, 905.177514792899 average response time

SELECT 
    strftime('%H', timestamp) AS hour,
    AVG(response_time_ms) AS avg_response_time
FROM 
    request_logs
GROUP BY 
    hour
ORDER BY 
    avg_response_time DESC
LIMIT 1;


-- Query to Find IPs that sent more than 100 requests with a 429 status code

SELECT 
    ip_address,
    COUNT(*) AS request_count
FROM 
    request_logs
WHERE 
    status_code = 429
GROUP BY 
    ip_address
HAVING 
    COUNT(*) > 100;

-- Query Results : 
-- ip_address        request_count

-- 119.103.226.136	  358
-- 122.157.29.219	  363
-- 148.57.203.182	  344
-- 17.237.57.99	      338
-- 81.233.238.12	  333


-- Query to Calculate the total bytes sent for requests where response time > 500ms.

SELECT 
    SUM(bytes_sent) AS total_bytes_sent
FROM 
    request_logs
WHERE 
    response_time_ms > 500;

-- Query Results : 

-- total_bytes_sent
-- 10719865