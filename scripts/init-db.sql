-- Database initialization script for PostgreSQL
-- This script sets up the initial database structure and extensions
--
-- Usage:
--   psql -v DB_PASSWORD="your_secure_password" -f init-db.sql
--
-- Note: 'password' is used as a fallback if DB_PASSWORD is not set, 
-- but you should always provide a secure password in production.

-- Enable required PostgreSQL extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";  -- For text search optimization

-- Create database user if not exists (for development)
-- Uses \gexec to execute dynamic SQL for conditional user creation
-- effectively replacing: CREATE USER honeypot_user WITH ENCRYPTED PASSWORD :'DB_PASSWORD';
-- wrapped in a check.
SELECT format(
    'CREATE USER honeypot_user WITH ENCRYPTED PASSWORD %L',
    COALESCE(:'DB_PASSWORD', 'password')
)
WHERE NOT EXISTS (
    SELECT FROM pg_catalog.pg_roles WHERE rolname = 'honeypot_user'
) \gexec

-- Grant necessary privileges
GRANT ALL PRIVILEGES ON DATABASE honeypot_api TO honeypot_user;
GRANT ALL ON SCHEMA public TO honeypot_user;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO honeypot_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO honeypot_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO honeypot_user;