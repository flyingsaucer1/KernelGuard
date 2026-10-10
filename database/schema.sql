CREATE DATABASE IF NOT EXISTS KernelGuard;
USE KernelGuard;

CREATE TABLE users (
    user_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    role VARCHAR(30),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE sessions (
    session_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    login_time DATETIME,
    logout_time DATETIME,
    login_status VARCHAR(20),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE TABLE devices (
    device_id INT AUTO_INCREMENT PRIMARY KEY,
    device_identifier VARCHAR(100) NOT NULL UNIQUE,
    device_type VARCHAR(30),
    device_name VARCHAR(100),
    is_known BOOLEAN DEFAULT FALSE
);

CREATE TABLE activity_events (
    event_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    session_id INT,
    device_id INT,
    event_time DATETIME NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    process_name VARCHAR(100),
    resource VARCHAR(255),
    source VARCHAR(50),
    event_hash VARCHAR(64) UNIQUE,
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id),
    FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE TABLE alerts (
    alert_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    event_id INT,
    alert_time DATETIME,
    alert_type VARCHAR(50),
    severity VARCHAR(20),
    reason VARCHAR(255),
    status VARCHAR(20),
    FOREIGN KEY (user_id) REFERENCES users(user_id),
    FOREIGN KEY (event_id) REFERENCES activity_events(event_id)
);
