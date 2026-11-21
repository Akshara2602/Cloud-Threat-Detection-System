
CREATE DATABASE IF NOT EXISTS cloud_threat_detection;

USE cloud_threat_detection;

-- 1. Users table
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('admin','analyst','viewer') DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 2. Security events table
CREATE TABLE security_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(255) UNIQUE,
    event_source VARCHAR(100),
    event_name VARCHAR(150),
    user_identity VARCHAR(255),
    source_ip VARCHAR(50),
    region VARCHAR(100),
    resource_name VARCHAR(255),
    event_data JSON,
    event_status VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Alerts table
CREATE TABLE alerts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    event_id VARCHAR(255),
    threat_type VARCHAR(150),
    description TEXT,
    severity ENUM('LOW','MEDIUM','HIGH','CRITICAL'),
    risk_score INT,
    source_ip VARCHAR(50),
    affected_resource VARCHAR(255),
    status ENUM('OPEN','INVESTIGATING','RESOLVED')
        DEFAULT 'OPEN',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP NULL
);

-- 4. Incidents table
CREATE TABLE incidents (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    alert_id BIGINT NOT NULL,
    assigned_to INT NULL,
    incident_title VARCHAR(255),
    investigation_notes TEXT,
    incident_status ENUM(
        'OPEN','IN_PROGRESS','CLOSED'
    ) DEFAULT 'OPEN',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id)
);

-- 5. Notifications table
CREATE TABLE notifications (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    alert_id BIGINT NOT NULL,
    recipient VARCHAR(255),
    notification_type VARCHAR(50),
    message TEXT,
    delivery_status VARCHAR(50),
    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (alert_id) REFERENCES alerts(id)
);

-- 6. Detection rules table
CREATE TABLE detection_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_name VARCHAR(150) NOT NULL,
    description TEXT,
    event_pattern VARCHAR(255),
    severity VARCHAR(20),
    threshold_value INT DEFAULT 1,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. Audit logs table
CREATE TABLE audit_logs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(255),
    details TEXT,
    ip_address VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Indexes for faster searches
CREATE INDEX idx_event_ip
ON security_events(source_ip);

CREATE INDEX idx_event_name
ON security_events(event_name);

CREATE INDEX idx_alert_severity
ON alerts(severity);

CREATE INDEX idx_alert_status
ON alerts(status);

CREATE INDEX idx_alert_created
ON alerts(created_at);
