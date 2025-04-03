-- This will run automatically only if flyway is told to look in velostone/cryptography as well as db/migration
CREATE SCHEMA IF NOT EXISTS ${flyway:defaultSchema};
CREATE TABLE IF NOT EXISTS ${flyway:defaultSchema}.vault (
    id UUID PRIMARY KEY,
    encrypted_contents text NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL
);
