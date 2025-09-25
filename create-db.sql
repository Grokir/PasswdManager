CREATE DATABASE IF NOT EXISTS db_passwd_manager;


CREATE TABLE IF NOT EXISTS credentials(  
    id INT NOT NULL PRIMARY KEY AUTO_INCREMENT COMMENT 'Primary Key',
    login   VARCHAR(255) NOT NULL,
    passwd  VARCHAR(255) NOT NULL
);

USE db_passwd_manager;

INSERT INTO `credentials` VALUE (0, "admin", "P@s5W0rD");

INSERT INTO `credentials` (login, passwd) VALUE ("test_user", "test_user_pasword");


SELECT * FROM credentials;