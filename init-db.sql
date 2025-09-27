
USE db_passwd_manager;

INSERT INTO `credentials` VALUE ("admin", "P@s5W0rD");
DELETE FROM user_data;
INSERT INTO `credentials` (login, passwd) VALUE ("test_user", "test_user_pasword");

DELETE FROM user_data where login = "IvanovPP@example.org"; 

SELECT `ADD_NEW_USER`(
    "IvanovPP@example.org", 
    "87fdd2e5d24a5e380a16dd7e40a1638b6c630aa683939d8b9fd0e8631ff9fcbf",
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