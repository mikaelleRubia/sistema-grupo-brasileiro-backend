DO 
$$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'grupobrasileiro') THEN
        EXECUTE 'CREATE DATABASE grupobrasileiro';
    END IF;
END
$$;
