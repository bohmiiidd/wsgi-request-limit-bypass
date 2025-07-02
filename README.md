# wsgi-request-limit-bypass
Proof of Concept for a denial-of-service (DoS) vulnerability in Werkzeug’s WSGI request handling that allows bypassing the max_content_length limit, causing servers to hang when processing infinite or excessively large HTTP request bodies.
