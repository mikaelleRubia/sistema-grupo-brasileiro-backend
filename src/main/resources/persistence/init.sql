DO 
$$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'grupobrasileiro') THEN
        PERFORM dblink_connect('dbname=postgres');
        EXECUTE 'CREATE DATABASE grupobrasileiro';
    END IF;
END
$$;
