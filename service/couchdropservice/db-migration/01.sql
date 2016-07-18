CREATE TABLE accounts (
  email_address varchar(500) DEFAULT NULL,
  password varchar(500) DEFAULT NULL,
  endpoint__amazon_s3_access_key_id varchar(500) DEFAULT NULL,
  endpoint__amazon_s3_access_secret_key varchar(500) DEFAULT NULL,
  PRIMARY KEY (email_address)
);

alter table accounts add column endpoint__amazon_s3_bucket varchar(500) default null;

CREATE TABLE tokens (
  token varchar(500) DEFAULT NULL,
  email_address varchar(500) DEFAULT NULL,
  PRIMARY KEY (token)
);

CREATE TABLE audit (
  id varchar(500) DEFAULT NULL,
  token varchar(500) DEFAULT NULL,
  email_address varchar(500) DEFAULT NULL,
  filename varchar(500) default null,
  time TIMESTAMP default null,
  PRIMARY KEY (id)
);

CREATE TABLE temp_credentials (
  username varchar(500) DEFAULT NULL,
  password varchar(500) DEFAULT NULL,
  account_email_address varchar(500) DEFAULT NULL,
  PRIMARY KEY (username)
);

alter table tokens add column admin bool default true;
alter table accounts add column real_email_address varchar(500) default '';

alter table accounts add column endpoint__dropbox_enabled bool default false;
alter table accounts add column endpoint__amazon_s3_enabled bool default false;
alter table accounts add column endpoint__dropbox_access_token varchar(500) default '';
alter table accounts add column endpoint__dropbox_user_id varchar(500) default '';

alter table tokens add column authenticated_user varchar(500) default '';
alter table audit add column authenticated_user varchar(500) default '';

--- MIGRATION TO BETTER STRUCTURE ---
ALTER TABLE accounts RENAME email_address TO username;
ALTER TABLE accounts RENAME real_email_address TO email_address;

ALTER TABLE tokens RENAME email_address TO account;
ALTER TABLE audit RENAME email_address TO account;
ALTER TABLE temp_credentials RENAME account_email_address TO account;

