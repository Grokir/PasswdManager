
USE db_passwd_manager;

INSERT INTO `credentials` VALUE ("admin", "P@s5W0rD");
DELETE FROM user_data;
INSERT INTO `credentials` (login, passwd) VALUE ("test_user", "test_user_pasword");

SELECT `ADD_NEW_USER`(
    "IvanovPP@example.org", 
    "P@s5w0rD_AdM1n",
    "Иванов Пётр Петрович", 
    "Главный системный администратор",
    "admin"
);

SELECT `ADD_NEW_USER`(
    "CarinEYu@example.org", 
    "123#C@r1n#456",
    "Царин Эдуард Юзявич", 
    "Начальник финансового отдела",
    "user"
);

SELECT `ADD_NEW_USER`(
    "ProstovIA@example.org", 
    "654#Pr0stoV#321",
    "Простов Иван Александрович", 
    "Работник финансового отдела",
    "user"
);

SELECT `ADD_NEW_USER`(
    "UstalovaIMA@example.org", 
    "passw0rd",
    "Усталова Ирина Михайловна", 
    "Работник отдела кадров",
    "super_user"
);

SELECT * FROM credentials;
SELECT * FROM user_data;
SELECT * FROM user_roles;