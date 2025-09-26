-- Active: 1757331362613@@127.0.0.1@3306@db_passwd_manager
CREATE DATABASE IF NOT EXISTS db_passwd_manager;


CREATE TABLE IF NOT EXISTS `user_data` (  
    `login`       VARCHAR(256)    NOT NULL,
    `full_name`   TEXT            NOT NULL,
    `position`    TEXT,

    PRIMARY KEY (`login`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE IF NOT EXISTS `credentials` (  
    `login`   VARCHAR(256) NOT NULL,
    `passwd`  TEXT NOT NULL,
    
    PRIMARY KEY (`login`),
    KEY `login` (`login`),
    CONSTRAINT `creds_ibfk_1` FOREIGN KEY (`login`) REFERENCES `user_data` (`login`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

CREATE TABLE `user_roles` (
  `login`   VARCHAR(256) NOT NULL,
  `role`    enum('admin','super_user','user','guest','unauthorized') NOT NULL,

  PRIMARY KEY (`login`),
  KEY `login` (`login`),
  CONSTRAINT `roles_ibfk_1` FOREIGN KEY (`login`) REFERENCES `user_data` (`login`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;



USE db_passwd_manager;


DELIMITER //
-- func for all roles
SET GLOBAL log_bin_trust_function_creators = 1;
DROP FUNCTION `ADD_NEW_USER` //

CREATE FUNCTION IF NOT EXISTS `ADD_NEW_USER` (
    n_login      VARCHAR(256),
    n_passwd     TEXT,
    n_full_name  TEXT,
    n_position   TEXT,
    n_role       VARCHAR(256)
)
RETURNS VARCHAR(10)
BEGIN

    INSERT INTO `user_data`     VALUE (n_login, n_full_name, n_position);
    INSERT INTO `credentials`   VALUE (n_login, n_passwd);
    INSERT INTO `user_roles`    VALUE (n_login, n_role);

    RETURN "OK";

END //

DELIMITER ;


