CREATE TABLE users 
(
    id uuid primary key default gen_random_uuid(),
    email varchar(255) not null unique,
    password_hash varchar(255) not null,
    is_admin boolean not null default false
);

CREATE TABLE apps
(
    id uuid primary key default gen_random_uuid(),
    name varchar(255) not null unique,
    secret varchar(255) not null unique
);