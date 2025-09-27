import tkinter as tk
from tkinter import messagebox

import re
from string import punctuation

from receiver import Receiver


class GUI_APP:
  __window          = None
  __entry_username  = None
  __entry_password  = None
  __receiver        = Receiver()

  def __init__(self, window_size:str = "300x250") -> None:
    # Создание главного окна
    self.__window = tk.Tk()
    self.__window.title("Вход в систему")
    self.__window.geometry(window_size)  # Увеличил высоту для новой кнопки

    # Метка и поле для логина
    label_username = tk.Label(self.__window, text="Логин:")
    label_username.pack(pady=5)
    self.__entry_username = tk.Entry(self.__window)
    self.__entry_username.pack(pady=5)

    # Метка и поле для пароля
    label_password = tk.Label(self.__window, text="Пароль:")
    label_password.pack(pady=5)
    self.__entry_password = tk.Entry(self.__window, show="\u00B7")
    self.__entry_password.pack(pady=5)

    # Кнопки
    button_login = tk.Button(self.__window, text="Войти", command=self.__login)
    button_login.pack(side=tk.LEFT, padx=10, pady=10)

    button_cancel = tk.Button(self.__window, text="Отмена", command=self.__cancel)
    button_cancel.pack(side=tk.RIGHT, padx=10, pady=10)

    # Новая кнопка для демонстрации получения данных
    button_show = tk.Button(self.__window, text="Показать данные", command=self.__show_data)
    button_show.pack(pady=10)


  def run(self):
    # Запуск главного цикла
    self.__window.mainloop()


  def __login(self):
    username = self.__entry_username.get()
    password = self.__entry_password.get()
    # Логика входа (можно расширить)
    if username and password:
      if self.__passwd_check_correct(password):
        data:dict = {
          "login": username,
          "password": password
        }
        res_str:str = self.__receiver.POST(data)
        if res_str == "ok":
          messagebox.showinfo("Успех", f"Вход выполнен для пользователя: {username}")
        else:
          messagebox.showerror("Ошибка", res_str)
      else:
        messagebox.showerror("Ошибка", 
          "Некорректный пароль! Пароль должен быть длиной не менее 8 символов и содержать символы A-Z, a-z, 0-9 и спец. символы"
        )

    else:
      messagebox.showerror("Ошибка", "Пожалуйста, введите логин и пароль")

  def __cancel(self):
    self.__window.quit()

  def __show_data(self):
    username = self.__entry_username.get()
    password = self.__entry_password.get()

    messagebox.showinfo("Проверка", f"Вы ввели:\nЛогин: {username},\nПароль: {password}", icon="info")
    
  
  def __passwd_check_correct(self, password: str) -> bool:
    """
    returns True if the password characters 
    belong to a set of characters {A-Z, a-z, 
    special characters, and numbers} and password len = 8. 
    And returns False otherwise.
    """
    regex: str = "^[a-zA-Z" + str(punctuation) + "0-9]"
    pattern = re.compile(regex)
    return ( (pattern.search(password) is not None) and (len(password) >= 8) )

