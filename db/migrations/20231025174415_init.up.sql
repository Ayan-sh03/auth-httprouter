ALTER TABLE users
    ADD CONSTRAINT check_name_not_empty CHECK (name <> ''),
    ADD CONSTRAINT check_email_not_empty CHECK (email <> '');