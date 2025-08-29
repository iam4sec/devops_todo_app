-- PostgreSQL setup script
CREATE DATABASE todoapp;
CREATE USER todoapp_user WITH PASSWORD 'password';
GRANT ALL PRIVILEGES ON DATABASE todoapp TO todoapp_user;

-- Connect to todoapp database and create tables
\c todoapp;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "citext";