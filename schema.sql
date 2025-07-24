-- schema.sql
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('student', 'admin', 'pending_admin', 'system_admin')),
    admin_level TEXT CHECK (admin_level IN ('academic', 'hostel', 'facilities', 'administration', NULL)),
    admin_position TEXT CHECK (admin_position IN ('GFM', 'DAC', 'HOD', 'Dean', 'Principal', 'Secretary', 'Rector', 'Lab_In_Charge', 'Department_Admin', 'Facility_Manager', 'Office_Admin', NULL)),
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS complaints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL,
    admin_id INTEGER,
    category TEXT NOT NULL,
    subcategory TEXT NOT NULL,
    description TEXT NOT NULL,
    file_path TEXT,
    is_public BOOLEAN DEFAULT 0,
    upvotes INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'in_progress', 'resolved', 'escalated')),
    priority TEXT DEFAULT 'normal' CHECK (priority IN ('low', 'normal', 'high', 'urgent')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_escalation TIMESTAMP,
    escalation_level INTEGER DEFAULT 0,
    FOREIGN KEY (student_id) REFERENCES users (id),
    FOREIGN KEY (admin_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    complaint_id INTEGER NOT NULL,
    admin_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (complaint_id) REFERENCES complaints (id),
    FOREIGN KEY (admin_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    link TEXT,
    is_read BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    complaint_id INTEGER,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users (id),
    FOREIGN KEY (receiver_id) REFERENCES users (id),
    FOREIGN KEY (complaint_id) REFERENCES complaints (id)
);

CREATE TABLE IF NOT EXISTS upvotes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    complaint_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (complaint_id) REFERENCES complaints (id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    UNIQUE(complaint_id, user_id)
);

CREATE TABLE IF NOT EXISTS escalation_chain (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    position_level INTEGER NOT NULL,
    position_name TEXT NOT NULL,
    UNIQUE(category, position_level)
);

-- Insert escalation chains
INSERT OR IGNORE INTO escalation_chain (category, position_level, position_name) VALUES
-- Academic Issues
('academics', 1, 'GFM'),
('academics', 2, 'DAC'),
('academics', 3, 'HOD'),
('academics', 4, 'Dean'),
('academics', 5, 'Principal'),
('academics', 6, 'Secretary'),

-- Hostel Issues
('hostel', 1, 'Rector'),
('hostel', 2, 'Principal'),
('hostel', 3, 'Secretary'),

-- Facilities Issues
('facilities', 1, 'Lab_In_Charge'),
('facilities', 2, 'Department_Admin'),
('facilities', 3, 'Facility_Manager'),
('facilities', 4, 'Principal'),
('facilities', 5, 'Secretary'),

-- Administration Issues
('administration', 1, 'Department_Admin'),
('administration', 2, 'Office_Admin'),
('administration', 3, 'Principal'),
('administration', 4, 'Secretary');