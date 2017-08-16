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

alter table accounts add column endpoint__valid_public_key varchar(1000) default '';
alter table audit add column storage_engine varchar(1000) default '';


create table storage (
  id varchar(500) default null,
  account varchar(500) DEFAULT NULL,
  store_type varchar(100) default null,
  path varchar(500) default '/',

  endpoint__dropbox_access_token varchar(500) default '',
  endpoint__dropbox_user_id varchar(500) default '',
  endpoint__amazon_s3_access_key_id varchar(500) default '',
  endpoint__amazon_s3_access_secret_key varchar(500) default '',

  PRIMARY KEY (id)
);

insert into storage (id, account, store_type, endpoint__dropbox_access_token, endpoint__dropbox_user_id) (
  select username, username, 'dropbox', endpoint__dropbox_access_token, endpoint__dropbox_user_id from accounts where endpoint__dropbox_enabled = true
)

insert into storage (id, account, store_type, endpoint__amazon_s3_access_key_id, endpoint__amazon_s3_access_secret_key) (
  select username, username, 's3', endpoint__amazon_s3_access_key_id, endpoint__amazon_s3_access_secret_key from accounts where endpoint__amazon_s3_enabled = true
)

alter table storage add column permissions varchar(10) default 'rw';
alter table storage add column endpoint__amazon_s3_bucket varchar(100) default '';

alter table storage add column endpoint__webdav_username varchar(100) default '';
alter table storage add column endpoint__webdav_password varchar(100) default '';
alter table storage add column endpoint__webdav_hostname varchar(100) default '';
alter table storage add column endpoint__webdav_path varchar(500) default '';
alter table storage add column endpoint__webdav_protocol varchar(100) default '';

alter table temp_credentials add column public_key varchar(1000) default '';
alter table temp_credentials add column permissions_mode varchar(10) default '';
alter table temp_credentials add column permissions_path varchar(100) default '';

alter table accounts add column subscription_type varchar(100) default 'freeby';

alter table accounts add column email_confirmation_code varchar(100) default '';
alter table accounts add column email_confirmation_code_accepted bool default false;
alter table accounts add column reset_password_code varchar(100) default '';

alter table storage add column endpoint__googledrive_credentials varchar(5000) default '';

alter table audit add column storage_engine_id varchar(500) default '';
alter table audit add column event_type varchar(500) default 'upload';
alter table audit add column ip_address varchar(500) default '';
alter table audit add column success bool default true;
alter table audit add column additional_info varchar(5000) default '';

alter table accounts add column created_time TIMESTAMP  default now();

