-- V1__Create_PrintingType_Table.sql
CREATE TABLE IF NOT EXISTS "Tb_PrintingTypes" (
    id SERIAL PRIMARY KEY,
    description VARCHAR(255) NOT NULL
);