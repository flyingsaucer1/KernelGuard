USE KernelGuard;

INSERT INTO users (username, role)
VALUES
('ahmed', 'student'),
('ankit', 'student'),
('arshpreet', 'student');
INSERT INTO sessions
(user_id, login_time, logout_time, login_status)
VALUES
(1, '2026-10-06 09:00:00', '2026-10-06 13:00:00', 'SUCCESS'),
(2, '2026-10-06 09:15:00', '2026-10-06 12:30:00', 'SUCCESS'),
(3, '2026-10-06 09:30:00', NULL, 'SUCCESS');
INSERT INTO devices
(device_identifier, device_type, device_name, is_known)
VALUES
('USB001', 'USB', 'Ahmed USB Drive', TRUE),
('USB002', 'USB', 'Unknown USB Device', FALSE);
INSERT INTO activity_events
(user_id, session_id, device_id, event_time, event_type, process_name, resource, source, event_hash)
VALUES
(1, 1, NULL, '2026-10-06 10:15:00', 'LOGIN_SUCCESS', 'sshd', '/home/ahmed', 'auditd', 'hash001'),

(1, 1, NULL, '2026-10-06 11:00:00', 'FILE_ACCESS', 'code', '/home/ahmed/project/important.txt', 'auditd', 'hash002'),

(2, 2, 2, '2026-10-06 11:30:00', 'DEVICE_CONNECTED', 'udevd', 'USB002', 'auditd', 'hash003'),

(3, 3, NULL, '2026-10-06 22:45:00', 'FILE_ACCESS', 'cp', '/home/arshpreet/sensitive.txt', 'auditd', 'hash004');
