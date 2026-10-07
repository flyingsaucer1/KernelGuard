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
