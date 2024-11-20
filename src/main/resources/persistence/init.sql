DO
$$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_database WHERE datname = 'grupobrasileiro'
   ) THEN
      CREATE DATABASE grupobrasileiro;
   END IF;
END
$$;