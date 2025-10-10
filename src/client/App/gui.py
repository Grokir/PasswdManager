from sys import path as sys_path
sys_path.append("../App")

import tkinter as tk
from tkinter import messagebox, ttk

import re
from string import punctuation

import time
import threading 

from App.receiver import Receiver


class GUI_APP:
  __window          = None
  __login_frame     = None
  __admin_panel     = None
  __suser_panel     = None
  __user_panel      = None
  __guest_panel     = None

  __entry_username  = None
  __entry_password  = None
  __receiver        = Receiver()

  __current_user:       dict = {}
  __activity_frame:     dict = {
    "admin":        False,
    "super_user":   False,
    "user" :        False,
    "guest":        False,
    "login":        False,
    "admin_tree1":  False,
    "admin_tree2":  False,
    "su_tree":      False
  }

  __cnt_attempt: int  = 0

  def __init__(self, window_size:str = "800x600") -> None:
    # Создание главного окна
    self.__window: tk.Tk = tk.Tk()
    self.__window.title("Вход в систему")
    self.__window.geometry(window_size)

    self.__init_login_panel()
    self.__init_admin_panel()
    self.__init_super_user_panel()
    self.__init_user_panel()
    self.__init_guest_panel()


  def run(self):
    # Запуск главного цикла
    self.__window.mainloop()


  def __change_frame(self, frame:str):
    self.__activity_frame["login"] = False
    panel: tk.Frame = None

    match frame:
      case "admin":
        panel = self.__admin_panel
        self.__activity_frame["admin"] = True
      case "super_user":
        # panel = self.__suser_panel
        panel = self.__suser_panel
        self.__activity_frame["super_user"] = True
      case "user":
        panel = self.__user_panel
        self.__activity_frame["user"] = True
      case "guest":
        panel = self.__guest_panel
        self.__activity_frame["guest"] = True
    
    self.__login_frame.pack_forget()
    panel.pack(fill=tk.BOTH, expand=True)


  def __login(self, login_button):
    username: str = self.__entry_username.get()
    password: str = self.__entry_password.get()
    
    if username and password:
      if self.__login_check_correct(username):
        if self.__passwd_check_correct(password):
          messagebox.showinfo("Инфо", "Осуществляем вход в систему...\nЭто может занять какое-то время.")
          data: dict = {
            "login": username,
            "password": password
          }
          res_str: str = ""
          try:

            res_str = self.__receiver.login(data)

          except Exception as e:
            exc_str = str(e)
            messagebox.showerror("Ошибка", exc_str)
          
          if res_str == "ok":
            self.__current_user = self.__receiver.get_current_user({"login": username})
            messagebox.showinfo("Успех", f"Вход выполнен для пользователя: {username}")
            self.__current_user["password"] = password
            self.__change_frame(str(self.__current_user["role"]))
            self.__cnt_attempt = 0
          else:
            messagebox.showerror("Ошибка", res_str)
            self.__cnt_attempt += 1
            
        else:
          messagebox.showerror("Ошибка", 
            "Некорректный пароль! Пароль должен быть длиной не менее 8 символов и содержать символы A-Z, a-z, 0-9 и спец. символы"
          )
      else:
        messagebox.showerror("Ошибка", 
          "Некорректный логин! Логин должен содержать '@example.org', т.е. Вы должны иметь корпоративную почту."
        )

    else:
      messagebox.showerror("Ошибка", "Пожалуйста, введите логин и пароль")
    
    if self.__cnt_attempt < 3 and self.__cnt_attempt > 0:
      messagebox.showerror("Ошибка", f"Неверные данные. Осталось попыток: {3 - self.__cnt_attempt}")
    elif self.__cnt_attempt >= 3:
      minutes: int = 5
      messagebox.showerror("Блокировка", f"Превышено количество попыток. Доступ заблокирован на {minutes} минут.")
      login_button.config(state="disabled")  # Блокируем кнопку
      # Фоновая задержка
      def unlock():
        time.sleep(minutes * 60)
        login_button.config(state="normal")
        self.__cnt_attempt = 0 
      threading.Thread(target=unlock).start()
    

  def __cancel(self):
    self.__window.quit()

  def __logout(self):
    self.__activity_frame["login"] = True
    panel: tk.Frame = None

    frame: str = ""

    for k in self.__activity_frame.keys():
      if self.__activity_frame[k]:
        frame = k
        break

    match frame:
      case "admin":
        panel = self.__admin_panel
        self.__activity_frame["admin"] = False
      case "super_user":
        panel = self.__suser_panel
        self.__activity_frame["super_user"] = False
      case "user":
        panel = self.__user_panel
        self.__activity_frame["user"] = False
      case "guest":
        panel = self.__guest_panel
        self.__activity_frame["guest"] = False

    # Возвращаемся к авторизации: скрываем рабочий фрейм и показываем логин
    panel.pack_forget()
    self.__login_frame.pack(fill=tk.Y, expand=True)

    # Очищаем поля
    self.__entry_username.delete(0, tk.END)
    self.__entry_password.delete(0, tk.END)

  def __show_data(self):
    username: str = self.__entry_username.get()
    password: str = self.__entry_password.get()
    messagebox.showinfo("Проверка", f"Вы ввели:\nЛогин: {username},\nПароль: {password}", icon="info")
    
  def __passwd_check_correct(self, password: str) -> bool:
    """
    returns True if the password characters 
    belong to a set of characters {A-Z, a-z, 
    special characters, and numbers} and password len >= 8. 
    And returns False otherwise.
    """
    regex_list: list = ["[a-z]", "[A-Z]", f"[{str(punctuation)}]", "[0-9]"]
    regex_flag: bool = True
    for regex in regex_list: 
      pattern = re.compile(regex)
      if pattern.search(password) is None:
        regex_flag = False
        break

    return ( regex_flag and (len(password) >= 8) )
  
  def __login_check_correct(self, login: str) -> bool:
    """
    returns True if the login have postfix <@example.org> 
    and login len > len of postfix. 
    And returns False otherwise.
    """
    postfix: str = "@example.org"
    return ( (postfix in login) and (len(login) > len(postfix)) )

  
  def __init_login_panel(self) -> None:
    self.__activity_frame["login"] = True

    self.__login_frame        = tk.Frame(self.__window)
    self.__login_frame.pack(fill=tk.Y, expand=True)
    username_frame: tk.Frame  = tk.Frame(self.__login_frame)
    username_frame    .pack(side=tk.TOP, fill=tk.X, expand=True)
    password_frame: tk.Frame  = tk.Frame(username_frame)
    password_frame    .pack(side=tk.BOTTOM, fill=tk.X, expand=True)
    buttons_frame:  tk.Frame  = tk.Frame(self.__login_frame)
    buttons_frame     .pack(side=tk.BOTTOM, fill=tk.X, expand=True)


    # Метка и поле для логина
    label_username:         tk.Label  = tk.Label(username_frame, text="Логин: ")
    label_username        .pack(side=tk.LEFT, pady=5)
    self.__entry_username:  tk.Entry  = tk.Entry(username_frame, width=30)
    self.__entry_username .pack(side=tk.RIGHT, pady=5)

    # Метка и поле для пароля
    label_password:         tk.Label  = tk.Label(password_frame, text="Пароль:")
    label_password        .pack(side=tk.LEFT, pady=5)
    self.__entry_password:  tk.Entry  = tk.Entry(password_frame, show="*", width=30)
    self.__entry_password .pack(side=tk.RIGHT, pady=5)

    # Кнопки
    button_login:   tk.Button = tk.Button(buttons_frame, text="Войти", command=lambda: self.__login(button_login))
    button_login.pack(side=tk.LEFT, padx=10, pady=10)
    
    # Новая кнопка для демонстрации получения данных
    button_show:    tk.Button = tk.Button(buttons_frame, text="Показать данные", command=self.__show_data)
    button_show.pack(side=tk.LEFT, pady=10)

    # Кнопка отмены входа в систему (она же выход)
    button_cancel:  tk.Button = tk.Button(buttons_frame, text="Отмена", command=self.__cancel)
    button_cancel.pack(side=tk.RIGHT, padx=10, pady=10)

  def __admin_add_user_window(self):
    # Создаем новое окно
    change_window: tk.Toplevel = tk.Toplevel(self.__window)
    change_window.title("Добавление пользователя")
    change_window.geometry("500x300")
    change_window.resizable(False, False)

    # Фрейм для формы внутри окна
    frame:            tk.Frame = tk.Frame(change_window)
    frame         .pack(pady=20, padx=20)
    login_frame:      tk.Frame = tk.Frame(frame)
    login_frame   .pack(side=tk.TOP, fill=tk.X)
    passw_frame:      tk.Frame = tk.Frame(frame)
    passw_frame   .pack(side=tk.TOP, fill=tk.X)
    cpassw_frame:     tk.Frame = tk.Frame(frame)
    cpassw_frame  .pack(side=tk.TOP, fill=tk.X)
    fname_frame:      tk.Frame = tk.Frame(frame)
    fname_frame   .pack(side=tk.TOP, fill=tk.X)
    pos_frame:        tk.Frame = tk.Frame(frame)
    pos_frame     .pack(side=tk.TOP, fill=tk.X)
    role_frame:       tk.Frame = tk.Frame(frame)
    role_frame    .pack(side=tk.TOP, fill=tk.X)
    buttons_frame:    tk.Frame = tk.Frame(frame)
    buttons_frame .pack(side=tk.TOP, fill=tk.X)

    # Поле для логина
    label_login: tk.Label = tk.Label(login_frame, text="Логин пользователя:")
    label_login.pack(side=tk.LEFT, anchor=tk.W)
    entry_login: tk.Entry = tk.Entry(login_frame, width=30)
    entry_login.pack(side=tk.RIGHT, pady=2)

    # Поле для нового пароля
    label_password: tk.Label = tk.Label(passw_frame, text="Пароль:")
    label_password.pack(side=tk.LEFT, anchor=tk.W)
    entry_password: tk.Entry = tk.Entry(passw_frame, show="*", width=30)
    entry_password.pack(side=tk.RIGHT, pady=2)

    # Поле для подтверждения пароля
    label_confirm_password: tk.Label = tk.Label(cpassw_frame, text="Подтвердите пароль:")
    label_confirm_password.pack(side=tk.LEFT, anchor=tk.W)
    entry_confirm_password: tk.Entry = tk.Entry(cpassw_frame, show="*", width=30)
    entry_confirm_password.pack(side=tk.RIGHT, pady=2)

    # Поле для ФИО
    label_full_name: tk.Label = tk.Label(fname_frame, text="ФИО:")
    label_full_name.pack(side=tk.LEFT, anchor=tk.W)
    entry_full_name: tk.Entry = tk.Entry(fname_frame, width=30)
    entry_full_name.pack(side=tk.RIGHT, pady=2)

    # Поле для Должности
    label_position: tk.Label = tk.Label(pos_frame, text="Должность:")
    label_position.pack(side=tk.LEFT, anchor=tk.W)
    entry_position: tk.Entry = tk.Entry(pos_frame, width=30)
    entry_position.pack(side=tk.RIGHT, pady=2)

    # Поле для Роли
    label_role:     tk.Label      = tk.Label(role_frame, text="Роль:")
    label_role    .pack(side=tk.LEFT, anchor=tk.W)
    entry_role:     tk.StringVar  = tk.StringVar()
    combobox_role: ttk.Combobox   = ttk.Combobox(role_frame, textvariable=entry_role)
    combobox_role['values']       = ["admin", "super_user", "user", "guest"]
    combobox_role .pack(side=tk.RIGHT, pady=2)
    
    def add_user(window):
      login             :str = entry_login            .get()
      password          :str = entry_password         .get()
      confirm_password  :str = entry_confirm_password .get()
      full_name         :str = entry_full_name        .get()
      position          :str = entry_position         .get()
      role              :str = entry_role             .get()

      if (not login             or 
          not password          or 
          not confirm_password  or 
          not position          or
          not role
      ):
        messagebox.showerror("Ошибка", "Все поля обязательны для заполнения.")
        return
      
      if not self.__login_check_correct(login):
        messagebox.showerror("Ошибка", 
          "Некорректный логин! Логин должен содержать '@example.org'."
        )
        return

      if password != confirm_password:
        messagebox.showerror("Ошибка", "Пароли не совпадают.")
        return
      
      if not self.__passwd_check_correct(password):
        messagebox.showerror("Ошибка", 
          "Некорректный пароль! Пароль должен быть длиной не менее 8 символов и содержать символы A-Z, a-z, 0-9 и спец. символы"
        )
        return
         

      try:
        result: str = self.__receiver.add_user({
            "login":    self.__current_user["login"],
            "password": self.__current_user["password"],
            "add_data": {
              "login":      login,
              "password":   password,
              "full_name":  full_name,
              "position":   position,
              "role":       role
            }
        })
        if result == "ok":
          messagebox.showinfo("Успех", "Пользователь успешно добавлен.")
          # Очистить поля
          entry_login.delete(0, tk.END)
          entry_password.delete(0, tk.END)
          entry_confirm_password.delete(0, tk.END)
        else:
          messagebox.showerror("Ошибка", result)
      except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось добавить пользователя: {e}")

    # Кнопка изменения пароля
    button_change = tk.Button(buttons_frame, text="Добавить пользователя", command=lambda: add_user(change_window))
    button_change.pack(side=tk.LEFT, pady=10)

    # Кнопка отмены
    button_cancel = tk.Button(buttons_frame, text="Отмена", command=change_window.destroy)
    button_cancel.pack(side=tk.RIGHT)

  def __admin_del_user_window(self):
    # Создаем новое окно
    change_window: tk.Toplevel = tk.Toplevel(self.__window)
    change_window.title("Удаление пользователя")
    change_window.geometry("500x100")
    change_window.resizable(False, False)

    # Фрейм для формы внутри окна
    frame:            tk.Frame = tk.Frame(change_window)
    frame         .pack(pady=20, padx=20)
    login_frame:      tk.Frame = tk.Frame(frame)
    login_frame   .pack(side=tk.TOP, fill=tk.X)
    buttons_frame:    tk.Frame = tk.Frame(frame)
    buttons_frame.pack(side=tk.TOP, fill=tk.X)

    # Поле для логина
    label_login: tk.Label = tk.Label(login_frame, text="Логин пользователя:")
    label_login.pack(side=tk.LEFT, anchor=tk.W)
    entry_login: tk.Entry = tk.Entry(login_frame, width=30)
    entry_login.pack(side=tk.RIGHT, pady=2)

    
    def del_user(window):
      login: str = entry_login.get()

      if not login:
        messagebox.showerror("Ошибка", "Поле 'Логин' не заполнено")
        return

      if not self.__login_check_correct(login):
        messagebox.showerror("Ошибка", 
          "Некорректный логин! Логин должен содержать '@example.org'."
        )
        return

      
      try:
        result: str = self.__receiver.del_user({
          "login":    self.__current_user["login"],
          "password": self.__current_user["password"],
          "del_data": {
            "login": login
          }
        })
        if result == "ok":
          messagebox.showinfo("Успех", "Пользователь успешно УВОЛЕН! >:).")
          # Очистить поля
          entry_login.delete(0, tk.END)
        else:
          messagebox.showerror("Ошибка", result)
      except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось добавить пользователя: {e}")

    # Кнопка удаления пользователя
    button_change = tk.Button(buttons_frame, text="Удалить пользователя", command=lambda: del_user(change_window))
    button_change.pack(side=tk.LEFT)

    # Кнопка отмены
    button_cancel = tk.Button(buttons_frame, text="Отмена", command=change_window.destroy)
    button_cancel.pack(side=tk.RIGHT)



  def __admin_chg_passwd_window(self):
    # Создаем новое окно
    change_window: tk.Toplevel = tk.Toplevel(self.__window)
    change_window.title("Изменение пароля пользователя")
    change_window.geometry("500x200")
    change_window.resizable(False, False)

    # Фрейм для формы внутри окна
    frame:            tk.Frame = tk.Frame(change_window)
    frame         .pack(pady=20, padx=20)
    login_frame:      tk.Frame = tk.Frame(frame)
    login_frame   .pack(side=tk.TOP, fill=tk.X)
    passw_frame:      tk.Frame = tk.Frame(frame)
    passw_frame   .pack(side=tk.TOP, fill=tk.X)
    cpassw_frame:     tk.Frame = tk.Frame(frame)
    cpassw_frame  .pack(side=tk.TOP, fill=tk.X)
    buttons_frame:    tk.Frame = tk.Frame(frame)
    buttons_frame.pack(side=tk.TOP, fill=tk.X)


    # Поле для логина
    label_login: tk.Label = tk.Label(login_frame, text="Логин пользователя:")
    label_login.pack(side=tk.LEFT, anchor=tk.W)
    entry_login: tk.Entry = tk.Entry(login_frame, width=30)
    entry_login.pack(side=tk.RIGHT, pady=2)

    # Поле для нового пароля
    label_new_password: tk.Label = tk.Label(passw_frame, text="Новый пароль:")
    label_new_password.pack(side=tk.LEFT, anchor=tk.W)
    entry_new_password: tk.Entry = tk.Entry(passw_frame, show="*", width=30)
    entry_new_password.pack(side=tk.RIGHT, pady=2)

    # Поле для подтверждения пароля
    label_confirm_password: tk.Label = tk.Label(cpassw_frame, text="Подтвердите пароль:")
    label_confirm_password.pack(side=tk.LEFT, anchor=tk.W)
    entry_confirm_password: tk.Entry = tk.Entry(cpassw_frame, show="*", width=30)
    entry_confirm_password.pack(side=tk.RIGHT, pady=2)

    def change_password(window):
      login:            str = entry_login           .get()
      new_password:     str = entry_new_password    .get()
      confirm_password: str = entry_confirm_password.get()

      if not login or not new_password or not confirm_password:
        messagebox.showerror("Ошибка", "Все поля обязательны для заполнения.")
        return

      if new_password != confirm_password:
        messagebox.showerror("Ошибка", "Пароли не совпадают.")
        return

      if not self.__passwd_check_correct(new_password):
        messagebox.showerror("Ошибка", 
          "Некорректный пароль! Пароль должен быть длиной не менее 8 символов и содержать символы A-Z, a-z, 0-9 и спец. символы"
        )
        return

      try:
        result: str = self.__receiver.change_password({
          "login":    self.__current_user["login"],
          "password": self.__current_user["password"],
          "upd_data": {
            "login":  login,
            "new_password": new_password
          }
        })
        if result == "ok":
          messagebox.showinfo("Успех", "Пароль успешно изменён.")
          # Очистить поля
          entry_login.delete(0, tk.END)
          entry_new_password.delete(0, tk.END)
          entry_confirm_password.delete(0, tk.END)
        else:
          messagebox.showerror("Ошибка", result)
      except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось изменить пароль: {e}")

    # Кнопка изменения пароля
    button_change = tk.Button(buttons_frame, text="Изменить пароль", command=lambda: change_password(change_window))
    button_change.pack(side=tk.LEFT, pady=10)

    # Кнопка отмены
    button_cancel = tk.Button(buttons_frame, text="Отмена", command=change_window.destroy)
    button_cancel.pack(side=tk.RIGHT)


  def __own_chg_passwd_window(self):
    # Создаем новое окно
    change_window: tk.Toplevel = tk.Toplevel(self.__window)
    change_window.title("Изменение пароля пользователя")
    change_window.geometry("500x150")
    change_window.resizable(False, False)

    # Фрейм для формы внутри окна
    frame:            tk.Frame = tk.Frame(change_window)
    frame         .pack(pady=20, padx=20)
    passw_frame:      tk.Frame = tk.Frame(frame)
    passw_frame   .pack(side=tk.TOP, fill=tk.X)
    cpassw_frame:     tk.Frame = tk.Frame(frame)
    cpassw_frame  .pack(side=tk.TOP, fill=tk.X)
    buttons_frame:    tk.Frame = tk.Frame(frame)
    buttons_frame .pack(side=tk.TOP, fill=tk.X)

    # Поле для нового пароля
    label_new_password: tk.Label = tk.Label(passw_frame, text="Новый пароль:")
    label_new_password.pack(side=tk.LEFT, anchor=tk.W)
    entry_new_password: tk.Entry = tk.Entry(passw_frame, show="*", width=30)
    entry_new_password.pack(side=tk.RIGHT, pady=2)

    # Поле для подтверждения пароля
    label_confirm_password: tk.Label = tk.Label(cpassw_frame, text="Подтвердите пароль:")
    label_confirm_password.pack(side=tk.LEFT, anchor=tk.W)
    entry_confirm_password: tk.Entry = tk.Entry(cpassw_frame, show="*", width=30)
    entry_confirm_password.pack(side=tk.RIGHT, pady=2)

    def change_password(window):
      new_password:     str = entry_new_password    .get()
      confirm_password: str = entry_confirm_password.get()

      if not new_password or not confirm_password:
        messagebox.showerror("Ошибка", "Все поля обязательны для заполнения.")
        return

      if new_password != confirm_password:
        messagebox.showerror("Ошибка", "Пароли не совпадают.")
        return
      
      if not self.__passwd_check_correct(new_password):
        messagebox.showerror("Ошибка", 
          "Некорректный пароль! Пароль должен быть длиной не менее 8 символов и содержать символы A-Z, a-z, 0-9 и спец. символы"
        )
        return

      
      try:
        result: str = self.__receiver.change_password({
          "login":    self.__current_user["login"],
          "password": self.__current_user["password"],
          "upd_data": {
            "login":  self.__current_user["login"],
            "new_password": new_password
          }
        })
        if result == "ok":
          messagebox.showinfo("Успех", "Пароль успешно изменён.")
          entry_new_password.delete(0, tk.END)
          entry_confirm_password.delete(0, tk.END)
        else:
          messagebox.showerror("Ошибка", result)
      except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось изменить пароль: {e}")

    # Кнопка изменения пароля
    button_change = tk.Button(buttons_frame, text="Изменить пароль", command=lambda: change_password(change_window))
    button_change.pack(side=tk.LEFT, pady=10)

    # Кнопка отмены
    button_cancel = tk.Button(buttons_frame, text="Отмена", command=change_window.destroy)
    button_cancel.pack(side=tk.RIGHT)



  def __init_admin_panel(self) -> None:
    def load_table_user_data():
      if self.__activity_frame["admin_tree2"]:
        self.__admin_tree2.pack_forget()
        self.__scrollbar2 .pack_forget()
        self.__activity_frame["admin_tree2"] = False

      # отрисуем таблицу и выведем данные
      self.__admin_tree1.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
      self.__scrollbar1 .pack(side=tk.LEFT, fill=tk.Y)
      self.__activity_frame["admin_tree1"] = True
      
      for item in self.__admin_tree1.get_children():
        self.__admin_tree1.delete(item)

      try:
        data_dict = self.__receiver.get_all_users(
          {
            "login": self.__current_user["login"], 
            "role":  self.__current_user["role"]
          }
        )  # Предполагаем, что возвращает список словарей
        # Вставляем данные в таблицу
        for i in range(len(data_dict)):
          self.__admin_tree1.insert("", tk.END, values=(
            data_dict[i]["login"], 
            data_dict[i]["full_name"], 
            data_dict[i]["position"],
            data_dict[i]["role"]
          ))
      except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось загрузить данные: {e}")

    def load_table_log_data():
        def parse_log(log_line:str) -> tuple[str, str]:
          timestamp_end:int = log_line.find(']')
          timestamp:    str = log_line[1:timestamp_end]

          # Остальная часть строки
          log_message:  str = log_line[timestamp_end+2:].strip("'")

          return timestamp, log_message

        # закроем другое дерево, если оно активно
        if self.__activity_frame["admin_tree1"]:
          self.__admin_tree1.pack_forget()
          self.__scrollbar1.pack_forget()
          self.__activity_frame["admin_tree1"] = False

        # отрисуем таблицу и выведем данные
        self.__admin_tree2.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.__scrollbar2 .pack(side=tk.LEFT, fill=tk.Y)
        self.__activity_frame["admin_tree2"] = True

        for item in self.__admin_tree2.get_children():
          self.__admin_tree2.delete(item)
          
        try:
            data_list = self.__receiver.get_logs(
              {
                "login": self.__current_user["login"], 
                "role":  self.__current_user["role"]
              }
            )  # Предполагаем, что возвращает список словарей
            
            # Вставляем данные в таблицу
            for i in range(len(data_list)):
              time, msg = parse_log(data_list[i][:-1])
              self.__admin_tree2.insert("", tk.END, values=(time, msg))

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить данные: {e}")

    def close_tables():
        if self.__activity_frame["admin_tree1"]:
          self.__admin_tree1.pack_forget()
          self.__activity_frame["admin_tree1"] = False
          self.__scrollbar1 .pack_forget()

        if self.__activity_frame["admin_tree2"]:
          self.__admin_tree2.pack_forget()
          self.__activity_frame["admin_tree2"] = False
          self.__scrollbar2 .pack_forget()

    def print_data():
      messagebox.showinfo(
        "Информация", 
        f"Вы Админ\nЛогин: {self.__current_user["login"]},\n" + 
        f"ФИО: {self.__current_user["full_name"]}\n" + 
        f"Должность: {self.__current_user["position"]}", 
        icon="info"
      )


    self.__admin_panel = tk.Frame(self.__window)

    header_frame: tk.Frame                 = tk.Frame(self.__admin_panel)
    header_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    user_data_buttons_frame: tk.Frame      = tk.Frame(self.__admin_panel)
    user_data_buttons_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    table_buttons_frame: tk.Frame          = tk.Frame(self.__admin_panel)
    table_buttons_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    table_frame: tk.Frame                  = tk.Frame(self.__admin_panel)
    table_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)



    button_logout: tk.Button               = tk.Button(
      header_frame, text="Выход", command=self.__logout
    )
    button_logout.pack(side=tk.RIGHT, padx=10)

    button_print_data:tk.Button            = tk.Button(
      header_frame, text="Показать данные пользователя", command=print_data
    )
    button_print_data.pack(side=tk.RIGHT, padx=10, pady=10)


    # Пример элементов рабочей панели (можно добавить больше)
    button_users_list: tk.Button           = tk.Button(
      table_buttons_frame, text="Получить список работников", command=load_table_user_data
    )
    button_users_list.pack(side=tk.LEFT, padx=10, pady=10)


    button_logs: tk.Button                 = tk.Button(
      table_buttons_frame, text="Показать логи", command=load_table_log_data
    )
    button_logs.pack(side=tk.LEFT,padx=10, pady=10)


    button_close_tables: tk.Button         = tk.Button(
      table_buttons_frame, text="Закрыть панель", command=close_tables
    )
    button_close_tables.pack(side=tk.RIGHT, pady=10)
    

    button_open_change_password: tk.Button = tk.Button(
      user_data_buttons_frame, text="Изменить пароль пользователя", command=self.__admin_chg_passwd_window
    )
    button_open_change_password.pack(side=tk.LEFT, pady=10)


    button_add_user: tk.Button             = tk.Button(
      user_data_buttons_frame, text="Добавить нового пользователя", command=self.__admin_add_user_window
    )
    button_add_user.pack(side=tk.LEFT, pady=10)


    button_del_user: tk.Button             = tk.Button(
      user_data_buttons_frame, text="Удалить пользователя", command=self.__admin_del_user_window
    )
    button_del_user.pack(side=tk.LEFT, pady=10)




# Создаём фрейм для таблицы
    # Создаём Treeview (таблицу) с столбцами
    self.__admin_tree1: ttk.Treeview       = ttk.Treeview(
      table_frame, columns=("login", "ФИО", "Должность", "Роль"), show="headings"
    )

    # Определяем заголовки столбцов
    self.__admin_tree1.heading("login", text="login")
    self.__admin_tree1.heading("ФИО", text="ФИО")
    self.__admin_tree1.heading("Должность", text="Должность")
    self.__admin_tree1.heading("Роль", text="Роль")

    # Устанавливаем ширину столбцов (опционально)
    self.__admin_tree1.column("login", width=50)
    self.__admin_tree1.column("ФИО", width=150)
    self.__admin_tree1.column("Должность", width=100)
    self.__admin_tree1.column("Роль", width=100)

    # Добавляем scrollbar для прокрутки
    self.__scrollbar1: ttk.Scrollbar        = ttk.Scrollbar(
      table_frame, orient=tk.VERTICAL, command=self.__admin_tree1.yview
    )
    self.__admin_tree1.configure(yscroll=self.__scrollbar1.set)

    

    self.__admin_tree2: ttk.Treeview       = ttk.Treeview(
      table_frame, columns=("Дата и Время", "Сообщение"), show="headings"
    )

    # Определяем заголовки столбцов
    self.__admin_tree2.heading("Дата и Время", text="Дата и Время")
    self.__admin_tree2.heading("Сообщение", text="Сообщение")

    # Устанавливаем ширину столбцов (опционально)
    self.__admin_tree2.column("Дата и Время", width=100)
    self.__admin_tree2.column("Сообщение", width=500)

    self.__scrollbar2: ttk.Scrollbar        = ttk.Scrollbar(
      table_frame, orient=tk.VERTICAL, command=self.__admin_tree2.yview
    )
    # Добавляем scrollbar для прокрутки
    self.__admin_tree2.configure(yscroll=self.__scrollbar2.set)



#############################################################################


  def __init_super_user_panel(self) -> None:
    def load_table_user_data():

      # отрисуем таблицу и выведем данные
      self.__su_tree  .pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
      self.__scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
      self.__activity_frame["su_tree"] = True
      
      for item in self.__su_tree.get_children():
            self.__su_tree.delete(item)
      # Пример: получаем данные из Receiver (адаптируйте под ваш API)
      try:
        # login:str = self.__entry_username.get()
        data_dict = self.__receiver.get_all_users(
          {
            "login": self.__current_user["login"], 
            "role":  self.__current_user["role"]
          }
        )  # Предполагаем, что возвращает список словарей
        # Вставляем данные в таблицу
        for i in range(len(data_dict)):
          self.__su_tree.insert("", tk.END, values=(
              data_dict[i]["login"], 
              data_dict[i]["full_name"], 
              data_dict[i]["position"],
              data_dict[i]["role"]
            )
          )
      except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось загрузить данные: {e}")

    def close_tables():
      if self.__activity_frame["su_tree"]:
        self.__su_tree  .pack_forget()
        self.__scrollbar.pack_forget()
        self.__activity_frame["su_tree"] = False

    self.__suser_panel: tk.Frame             = tk.Frame(self.__window)

    header_frame: tk.Frame                   = tk.Frame(self.__suser_panel)
    header_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=2)

    passwd_button_frame: tk.Frame            = tk.Frame(self.__suser_panel, height=20)
    passwd_button_frame.pack(fill=tk.X, expand=True)

    table_buttons_frame: tk.Frame            = tk.Frame(passwd_button_frame, height=50)
    table_buttons_frame.pack(side=tk.BOTTOM, fill=tk.X, expand=True)

    table_frame: tk.Frame                    = tk.Frame(self.__suser_panel)
    table_frame.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True, padx=10, pady=5)

    

    button_logout: tk.Button                 = tk.Button(header_frame, text="Выход", command=self.__logout)
    button_logout.pack(side=tk.RIGHT, fill=tk.Y, padx=10)
    
    button_print_data: tk.Button             = tk.Button(
      header_frame, text="Показать данные пользователя", command=lambda: messagebox.showinfo(
        "Информация", 
        f"Вы Привилегированный Пользователь\nЛогин: {self.__current_user["login"]},\n" + 
        f"ФИО: {self.__current_user["full_name"]}\n" + 
        f"Должность: {self.__current_user["position"]}", 
        icon="info"
      )
    )
    button_print_data.pack(side=tk.RIGHT, padx=10)

    button_open_change_password: tk.Button   = tk.Button(
      passwd_button_frame, text="Изменить пароль пользователя", command=self.__own_chg_passwd_window
    )
    button_open_change_password.pack(side=tk.RIGHT, padx=10)


    button_close_tables: tk.Button           = tk.Button(
      table_buttons_frame, text="Закрыть панель", command=close_tables
    )
    button_close_tables.pack(side=tk.RIGHT, padx=10)
    
    button_users_list: tk.Button             = tk.Button(
      table_buttons_frame, text="Получить список работников", command=load_table_user_data
    )
    button_users_list.pack(side=tk.RIGHT, padx=10)


    # Создаём Treeview (таблицу) с столбцами
    self.__su_tree: ttk.Treeview             = ttk.Treeview(
      table_frame, columns=("login", "ФИО", "Должность", "Роль"), show="headings"
    )

    # Определяем заголовки столбцов
    self.__su_tree.heading("login", text="login")
    self.__su_tree.heading("ФИО", text="ФИО")
    self.__su_tree.heading("Должность", text="Должность")
    self.__su_tree.heading("Роль", text="Роль")

    # Устанавливаем ширину столбцов (опционально)
    self.__su_tree.column("login", width=50)
    self.__su_tree.column("ФИО", width=150)
    self.__su_tree.column("Должность", width=100)
    self.__su_tree.column("Роль", width=100)

    # Добавляем scrollbar для прокрутки
    self.__scrollbar: ttk.Scrollbar          = ttk.Scrollbar(
      table_frame, orient=tk.VERTICAL, command=self.__su_tree.yview
    )
    self.__su_tree.configure(yscroll=self.__scrollbar.set)


#############################################################################


  def __init_user_panel(self) -> None:
    self.__user_panel = tk.Frame(self.__window)

    header_frame: tk.Frame                   = tk.Frame(self.__user_panel)
    header_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    button_logout: tk.Button                 = tk.Button(
      header_frame,
      text="Выход",
      command=self.__logout
    )
    button_logout.pack(side=tk.RIGHT, padx=10)

    # Пример элементов рабочей панели (можно добавить больше)
    button_print_data: tk.Button             = tk.Button(
      header_frame,
      text="Показать данные пользователя",
      command=lambda: messagebox.showinfo(
        "Информация", 
        f"Вы Привилегированный Пользователь\nЛогин: {self.__current_user["login"]},\n" + 
        f"ФИО: {self.__current_user["full_name"]}\n" + 
        f"Должность: {self.__current_user["position"]}", 
        icon="info"
      )
    )
    button_print_data.pack(side=tk.RIGHT, padx=10)

    button_open_change_password: tk.Button   = tk.Button(
      self.__user_panel,
      text="Изменить пароль пользователя",
      command=self.__own_chg_passwd_window
    )
    button_open_change_password.pack(pady=10)


#############################################################################


  def __init_guest_panel(self) -> None:
    self.__guest_panel = tk.Frame(self.__window)

    header_frame: tk.Frame       = tk.Frame(self.__guest_panel)
    header_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    button_logout: tk.Button     = tk.Button(header_frame, text="Выход", command=self.__logout)
    button_logout.pack(side=tk.RIGHT, padx=10)

    # Пример элементов рабочей панели (можно добавить больше)
    button_print_data: tk.Button = tk.Button(
      header_frame,
      text="Показать данные пользователя",
      command=lambda: messagebox.showinfo(
        "Информация", 
        f"Вы Гость\nЛогин: {self.__current_user["login"]},\nФИО: {self.__current_user["full_name"]}", 
        icon="info"
      )
    )
    button_print_data.pack(side=tk.RIGHT, padx=10)



