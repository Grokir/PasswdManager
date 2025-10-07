
USE db_passwd_manager;

/* INSERT INTO `credentials` VALUE ("admin", "P@s5W0rD"); */
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
    "0efff8469acaf45c079eaedb9158f77e66dc1ba971448075f57ce1bd6df039a0",
    "Царин Эдуард Юзявич", 
    "Начальник финансового отдела",
    "user"
);

SELECT `ADD_NEW_USER`(
    "ProstovIA@example.org", 
    "0f2c527f64d4d85a53cad03f3783d3ce2bcc15a712ff26395e7a4c2c6b2bdbdb",
    "Простов Иван Александрович", 
    "Работник финансового отдела",
    "user"
);

SELECT `ADD_NEW_USER`(
    "UstalovaIMA@example.org", 
    "cef7ae3760e8eed553d97dd05264c6b531828b88de722f5a4111314eae78f19f",
    "Усталова Ирина Михайловна", 
    "Работник отдела кадров",
    "super_user"
);

SELECT * FROM credentials;
SELECT * FROM user_data;
SELECT * FROM user_roles;

/* 
# Admin
# Login: IvanovPP@example.org
# Passw: P@s5w0rD_AdM1n

# User
# Login: ProstovIA@example.org
# Passw: 654#Pr0stoV#321

# User
# Login: UstalovaIMA@example.org
# Passw: passw0rd
## old pass    = passw0rd
## pass_hash   = cef7ae3760e8eed553d97dd05264c6b531828b88de722f5a4111314eae78f19f
## salt in int = 12622

# Login: "CarinEYu@example.org"
# Passw: "123#C@r1n#456" */