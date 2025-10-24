CREATE ROLE admin_user LOGIN PASSWORD 'secure_admin_pass';
CREATE ROLE app_user LOGIN PASSWORD 'secure_app_pass';

GRANT CONNECT ON DATABASE notes_db TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
