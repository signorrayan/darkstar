INSERT INTO Vulnerability (
    cve, title, affected_item, tool, confidence, severity, host,
    cvss, epss, summary, cwe, `references`, capec, solution, impact,
    access, age, pocs, kev
) VALUES (
    'CVE-2024-1234', 
    'Example Vulnerability Title', 
    'Affected Item X', 
    'Tool Y', 
    0.95, 
    'Critical', 
    'example.com', 
    9.8, 
    0.75, 
    'A vulnerability allowing attackers to escalate privileges.',
    'CWE-79', 
    'https://example.com/reference1, https://example.com/reference2',
    'CAPEC-88', 
    'Apply patch version 2.0 from vendor.', 
    'Data breach possible.',
    'Requires network access', 
    5, 
    'https://example.com/poc1, https://example.com/poc2', 
    TRUE
);
