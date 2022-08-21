drop database IF EXISTS spring_sec_jdbc;

create database spring_sec_jdbc;

use spring_sec_jdbc;

DROP TABLE if exists msd_users CASCADE;


CREATE  TABLE msd_users (
  username VARCHAR(45) NOT NULL ,
  password VARCHAR(45) NOT NULL ,
  enabled TINYINT NOT NULL DEFAULT 1 ,
  PRIMARY KEY (username)
  );
  
  
CREATE TABLE msd_user_roles (
  user_role_id int(11) NOT NULL AUTO_INCREMENT,
  username varchar(45) NOT NULL,
  role varchar(45) NOT NULL,
  PRIMARY KEY (user_role_id),
  UNIQUE KEY uni_username_role (role,username),
  KEY fk_username_idx (username),
  CONSTRAINT fk_username FOREIGN KEY (username) REFERENCES msd_users (username)
  );
  
  
  
INSERT INTO msd_users(username,password,enabled) VALUES ('db_admin','db_admin', true);
INSERT INTO msd_users(username,password,enabled) VALUES ('db_dba','db_dba', true);
INSERT INTO msd_users(username,password,enabled) VALUES ('db_user','db_user', true);

INSERT INTO msd_user_roles (username, role) VALUES ('db_admin', 'ROLE_MSD_ADMIN');
INSERT INTO msd_user_roles (username, role) VALUES ('db_dba', 'ROLE_MSD_DBA');
INSERT INTO msd_user_roles (username, role) VALUES ('db_user', 'ROLE_MSD_USER');

commit;
