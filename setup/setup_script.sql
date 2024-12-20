-- Step 1: Create a User with Full Privileges
CREATE USER 'datamanager'@'%' IDENTIFIED BY 'asjaskld29847ajksda#sdas';

-- Grant ALL PRIVILEGES to the user on all databases
GRANT ALL PRIVILEGES ON *.* TO 'datamanager'@'%' WITH GRANT OPTION;

-- Flush privileges to apply changes
FLUSH PRIVILEGES;

-- Step 2: Create the 'test' Database (if not exists)
CREATE DATABASE IF NOT EXISTS test;

-- Use the 'test' Database
USE test;

-- Step 3: Create the 'Vulnerability' Table
CREATE TABLE Vulnerability (
    cve VARCHAR(255) NOT NULL, -- CVE identifier (unique vulnerability ID)
    title VARCHAR(255), -- Title or short description of the vulnerability
    affected_item VARCHAR(255), -- The item or system affected by the vulnerability
    tool VARCHAR(255), -- The tool used to identify the vulnerability
    confidence INT, -- Confidence level of the vulnerability detection
    severity VARCHAR(50), -- Severity level of the vulnerability (e.g., Low, Medium, High)
    host VARCHAR(255), -- Host affected by the vulnerability
    cvss DECIMAL(4,2), -- CVSS score (Common Vulnerability Scoring System)
    epss DECIMAL(4,2), -- EPSS score (Exploit Prediction Scoring System)
    summary TEXT, -- Detailed summary or description of the vulnerability
    cwe VARCHAR(255), -- CWE identifier (Common Weakness Enumeration)
    `references` TEXT, -- References or links for more information
    capec VARCHAR(255), -- CAPEC identifier (Common Attack Pattern Enumeration and Classification)
    solution TEXT, -- Solution or mitigation for the vulnerability
    impact TEXT, -- Impact or consequences of the vulnerability
    access VARCHAR(255), -- Access vector or requirements for exploiting the vulnerability
    age INT, -- Age of the vulnerability in days
    pocs TEXT, -- Proof of concepts (PoCs) or exploitation examples
    kev BOOLEAN -- Known Exploited Vulnerability (True/False)
);

-- Step 4: Create the 'asmevents' Table
CREATE TABLE asmevents (
    id INT(11) NOT NULL AUTO_INCREMENT, -- Unique identifier for the event
    event_type VARCHAR(50) DEFAULT NULL, -- Type of the event
    event_data TEXT DEFAULT NULL, -- Detailed data about the event
    ip_address TEXT DEFAULT NULL, -- IP address associated with the event
    source_module VARCHAR(50) DEFAULT NULL, -- Module that generated the event
    scope_distance INT(11) DEFAULT NULL, -- Scope distance or related measure
    event_tags TEXT DEFAULT NULL, -- Tags associated with the event
    `time` DATETIME DEFAULT NULL, -- Timestamp of the event
    PRIMARY KEY (id) -- Set 'id' as the primary key
);
