import tkinter as tk
from tkinter import messagebox, ttk

import re
from string import punctuation

from receiver import Receiver


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

  def __init__(self, window_size:str = "800x600") -> None:
    # Создание главного окна
    self.__window = tk.Tk()
    self.__window.title("Вход в систему")
    self.__window.geometry(window_size)  # Увеличил высоту для новой кнопки
    
    # self.__login_frame = tk.Frame(self.__window)
    # self.__admin_panel = tk.Frame(self.__window)

    self.__init_login_panel()
    self.__init_admin_panel()
    self.__init_super_user_panel()
    self.__init_user_panel()
    # self.__init_guest_panel()




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
        # panel = self.__guest_panel
        panel = self.__user_panel
        self.__activity_frame["guest"] = True
    
    self.__login_frame.pack_forget()
    panel.pack(fill=tk.BOTH, expand=True)


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
        res_str:str = ""
        try:

          res_str = self.__receiver.login(data)

        except Exception as e:
          print(e.args)
          exc_str = str(e)
          # messagebox.showerror("Ошибка", "Ошибка подключения к серверу")
          messagebox.showerror("Ошибка", exc_str)
        
        if res_str == "ok":
          self.__current_user = self.__receiver.GET_current_user({"login": username})
          messagebox.showinfo("Успех", f"Вход выполнен для пользователя: {username}")
          self.__current_user["password"] = password
          self.__change_frame(str(self.__current_user["role"]))
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

  def __logout(self):
    self.__activity_frame["login"] = True
    panel: tk.Frame = None

    frame:str = ""

    for k in self.__activity_frame.keys():
      if self.__activity_frame[k]:
        frame = k
        break

    match frame:
      case "admin":
        panel = self.__admin_panel
        self.__activity_frame["admin"] = False
      case "super_user":
        # panel = self.__suser_panel
        panel = self.__suser_panel
        self.__activity_frame["super_user"] = False
      case "user":
        panel = self.__user_panel
        self.__activity_frame["user"] = False
      case "guest":
        # panel = self.__guest_panel
        panel = self.__user_panel
        self.__activity_frame["guest"] = False

    # Возвращаемся к авторизации: скрываем рабочий фрейм и показываем логин
    panel.pack_forget()
    self.__login_frame.pack(fill=tk.BOTH, expand=True)

    # Очищаем поля
    self.__entry_username.delete(0, tk.END)
    self.__entry_password.delete(0, tk.END)

  def __show_data(self):
    username = self.__entry_username.get()
    password = self.__entry_password.get()
    messagebox.showinfo("Проверка", f"Вы ввели:\nЛогин: {username},\nПароль: {password}", icon="info")
    
  def __passwd_check_correct(self, password: str) -> bool:
    """
    returns True if the password characters 
    belong to a set of characters {A-Z, a-z, 
    special characters, and numbers} and password len >= 8. 
    And returns False otherwise.
    """
    regex: str = "^[a-zA-Z" + str(punctuation) + "0-9]"
    pattern = re.compile(regex)
    return ( (pattern.search(password) is not None) and (len(password) >= 8) )
  
  def __init_login_panel(self) -> None:
    self.__activity_frame["login"] = True

    self.__login_frame = tk.Frame(self.__window)
    self.__login_frame.pack(fill=tk.BOTH, expand=True)

    # Метка и поле для логина
    label_username = tk.Label(self.__login_frame, text="Логин:")
    label_username.pack(pady=5)
    self.__entry_username = tk.Entry(self.__login_frame)
    self.__entry_username.pack(pady=5)

    # Метка и поле для пароля
    label_password = tk.Label(self.__login_frame, text="Пароль:")
    label_password.pack(pady=5)
    self.__entry_password = tk.Entry(self.__login_frame, show="\u00B7")
    self.__entry_password.pack(pady=5)

    # Кнопки
    button_login = tk.Button(self.__login_frame, text="Войти", command=self.__login)
    button_login.pack(side=tk.LEFT, padx=10, pady=10)

    button_cancel = tk.Button(self.__login_frame, text="Отмена", command=self.__cancel)
    button_cancel.pack(side=tk.RIGHT, padx=10, pady=10)

    # Новая кнопка для демонстрации получения данных
    button_show = tk.Button(self.__login_frame, text="Показать данные", command=self.__show_data)
    button_show.pack(pady=10)


  def __admin_chg_passwd_window(self):
    # Создаем новое окно
    change_window = tk.Toplevel(self.__window)
    change_window.title("Изменение пароля пользователя")
    change_window.geometry("500x500")
    change_window.resizable(False, False)

    # Фрейм для формы внутри окна
    frame = tk.Frame(change_window)
    frame.pack(pady=20, padx=20)

    label_title = tk.Label(frame, text="Изменение пароля пользователя", font=("Arial", 14))
    label_title.pack(pady=10)

    # Поле для логина
    label_login = tk.Label(frame, text="Логин пользователя:")
    label_login.pack(anchor=tk.W)
    entry_login = tk.Entry(frame, width=30)
    entry_login.pack(pady=2)

    # Поле для нового пароля
    label_new_password = tk.Label(frame, text="Новый пароль:")
    label_new_password.pack(anchor=tk.W)
    entry_new_password = tk.Entry(frame, show="*", width=30)
    entry_new_password.pack(pady=2)

    # Поле для подтверждения пароля
    label_confirm_password = tk.Label(frame, text="Подтвердите пароль:")
    label_confirm_password.pack(anchor=tk.W)
    entry_confirm_password = tk.Entry(frame, show="*", width=30)
    entry_confirm_password.pack(pady=2)

    def change_password(window):
      login = entry_login.get()
      new_password = entry_new_password.get()
      confirm_password = entry_confirm_password.get()

      if not login or not new_password or not confirm_password:
        messagebox.showerror("Ошибка", "Все поля обязательны для заполнения.")
        return

      if new_password != confirm_password:
        messagebox.showerror("Ошибка", "Пароли не совпадают.")
        return

      # Здесь вызовите ваш API для изменения пароля
      # Предполагаем, что у вас есть метод self.__receiver.change_password(login, new_password, current_user_info)
      try:
          result = self.__receiver.change_password({
              "login": self.__current_user["login"],
              "password": self.__current_user["password"],
              "upd_data": {
                  "login": login,
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
    button_change = tk.Button(frame, text="Изменить пароль", command=lambda: change_password(change_window))
    button_change.pack(pady=10)

    # Кнопка отмены
    button_cancel = tk.Button(frame, text="Отмена", command=change_window.destroy)
    button_cancel.pack()

  def __own_chg_passwd_window(self):
    # Создаем новое окно
    change_window = tk.Toplevel(self.__window)
    change_window.title("Изменение пароля пользователя")
    change_window.geometry("400x400")
    change_window.resizable(False, False)

    # Фрейм для формы внутри окна
    frame = tk.Frame(change_window)
    frame.pack(pady=20, padx=20)

    label_title = tk.Label(frame, text="Изменение пароля пользователя", font=("Arial", 14))
    label_title.pack(pady=10)

    # Поле для нового пароля
    label_new_password = tk.Label(frame, text="Новый пароль:")
    label_new_password.pack(anchor=tk.W)
    entry_new_password = tk.Entry(frame, show="*", width=30)
    entry_new_password.pack(pady=2)

    # Поле для подтверждения пароля
    label_confirm_password = tk.Label(frame, text="Подтвердите пароль:")
    label_confirm_password.pack(anchor=tk.W)
    entry_confirm_password = tk.Entry(frame, show="*", width=30)
    entry_confirm_password.pack(pady=2)

    def change_password(window):
      new_password = entry_new_password.get()
      confirm_password = entry_confirm_password.get()

      if not new_password or not confirm_password:
        messagebox.showerror("Ошибка", "Все поля обязательны для заполнения.")
        return

      if new_password != confirm_password:
        messagebox.showerror("Ошибка", "Пароли не совпадают.")
        return

      # Здесь вызовите ваш API для изменения пароля
      # Предполагаем, что у вас есть метод self.__receiver.change_password(login, new_password, current_user_info)
      try:
          result = self.__receiver.change_password({
              "login": self.__current_user["login"],
              "password": self.__current_user["password"],
              "upd_data": {
                  "login": self.__current_user["login"],
                  "new_password": new_password
              }
          })
          if result == "ok":
              messagebox.showinfo("Успех", "Пароль успешно изменён.")
              # Очистить поля
              entry_new_password.delete(0, tk.END)
              entry_confirm_password.delete(0, tk.END)
          else:
              messagebox.showerror("Ошибка", result)
      except Exception as e:
          messagebox.showerror("Ошибка", f"Не удалось изменить пароль: {e}")

    # Кнопка изменения пароля
    button_change = tk.Button(frame, text="Изменить пароль", command=lambda: change_password(change_window))
    button_change.pack(pady=10)

    # Кнопка отмены
    button_cancel = tk.Button(frame, text="Отмена", command=change_window.destroy)
    button_cancel.pack()



  def __init_admin_panel(self) -> None:
    def load_table_user_data():
      if self.__activity_frame["admin_tree2"]:
        self.__admin_tree2.pack_forget()
        self.__activity_frame["admin_tree2"] = False

      # отрисуем таблицу и выведем данные
      self.__admin_tree1.pack(fill=tk.BOTH, expand=True)
      self.__activity_frame["admin_tree1"] = True
      
      for item in self.__admin_tree1.get_children():
        self.__admin_tree1.delete(item)
      # Пример: получаем данные из Receiver (адаптируйте под ваш API)
      try:
        # login:str = self.__entry_username.get()
        data_dict = self.__receiver.GET_all_users(
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
            timestamp: str = log_line[1:timestamp_end]

            # Остальная часть строки
            log_message:str = log_line[timestamp_end+2:].strip("'")

            return timestamp, log_message

        # закроем другое дерево, если оно активно
        if self.__activity_frame["admin_tree1"]:
            self.__admin_tree1.pack_forget()
            self.__activity_frame["admin_tree1"] = False

        # отрисуем таблицу и выведем данные
        self.__admin_tree2.pack(fill=tk.BOTH, expand=True)
        self.__activity_frame["admin_tree2"] = True

        for item in self.__admin_tree2.get_children():
            self.__admin_tree2.delete(item)
        # Пример: получаем данные из Receiver (адаптируйте под ваш API)
        try:
            # login:str = self.__entry_username.get()
            data_list = self.__receiver.GET_logs(
                {
                    "login": self.__current_user["login"], 
                    "role":  self.__current_user["role"]
                }
            )  # Предполагаем, что возвращает список словарей
            # Вставляем данные в таблицу
            for i in range(len(data_list)):
                time, msg = parse_log(data_list[i][:-1])
                self.__admin_tree2.insert("", tk.END, values=(time, msg))
                # print(line)

        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось загрузить данные: {e}")

    def close_tables():
        if self.__activity_frame["admin_tree1"]:
            self.__admin_tree1.pack_forget()
            self.__activity_frame["admin_tree1"] = False

        if self.__activity_frame["admin_tree2"]:
            self.__admin_tree2.pack_forget()
            self.__activity_frame["admin_tree2"] = False

        # self.__scrollbar.pack_forget()


    self.__admin_panel = tk.Frame(self.__window)

    header_frame = tk.Frame(self.__admin_panel)

    header_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    label_user_info = tk.Label(header_frame, text=f"admin", font=("Arial", 16), fg="blue")
    label_user_info.pack(side=tk.RIGHT)

    label_welcome = tk.Label(self.__admin_panel, text="", font=("Arial", 16))
    label_welcome.pack(pady=50)

    # Пример элементов рабочей панели (можно добавить больше)
    # button_action1 = tk.Button(self.__admin_panel, text="Действие 1", command=lambda: messagebox.showinfo("Действие", "Выполнено действие 1"))
    button_action1 = tk.Button(self.__admin_panel, text="Получить список работников", command=load_table_user_data)
    button_action1.pack(pady=10)

    button_action2 = tk.Button(self.__admin_panel, text="Показать логи", command=load_table_log_data)
    button_action2.pack(pady=10)

    button_close_tables = tk.Button(self.__admin_panel, text="Закрыть панель", command=close_tables)
    button_close_tables.pack(pady=10)

    button_open_change_password = tk.Button(self.__admin_panel, text="Изменить пароль пользователя", command=self.__admin_chg_passwd_window)
    button_open_change_password.pack(pady=10)

    button_logout = tk.Button(self.__admin_panel, text="Выход", command=self.__logout)
    button_logout.pack(pady=20)


# Создаём фрейм для таблицы
    table_frame = tk.Frame(self.__admin_panel)
    table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Создаём Treeview (таблицу) с столбцами
    self.__admin_tree1 = ttk.Treeview(table_frame, columns=("login", "ФИО", "Должность", "Роль"), show="headings")

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
    self.__scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.__admin_tree1.yview)
    self.__admin_tree1.configure(yscroll=self.__scrollbar.set)

    

    self.__admin_tree2 = ttk.Treeview(table_frame, columns=("Дата и Время", "Сообщение"), show="headings")

    # Определяем заголовки столбцов
    self.__admin_tree2.heading("Дата и Время", text="Дата и Время")
    self.__admin_tree2.heading("Сообщение", text="Сообщение")

    # Устанавливаем ширину столбцов (опционально)
    self.__admin_tree2.column("Дата и Время", width=100)
    self.__admin_tree2.column("Сообщение", width=500)

    # Добавляем scrollbar для прокрутки
    self.__admin_tree2.configure(yscroll=self.__scrollbar.set)
    self.__scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Кнопка для обновления таблицы
    # button_refresh = tk.Button(self.__admin_panel, text="Обновить таблицу", command=load_table_data)
    # button_refresh.pack(pady=10)

    # Загружаем данные при инициализации панели
    # self.load_table_data()



#############################################################################


  def __init_super_user_panel(self) -> None:
    def load_table_user_data():

      # отрисуем таблицу и выведем данные
      self.__su_tree.pack(fill=tk.BOTH, expand=True)
      self.__activity_frame["su_tree"] = True
      self.__scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
      
      for item in self.__su_tree.get_children():
            self.__su_tree.delete(item)
      # Пример: получаем данные из Receiver (адаптируйте под ваш API)
      try:
        # login:str = self.__entry_username.get()
        data_dict = self.__receiver.GET_all_users(
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
        self.__su_tree.pack_forget()
        self.__activity_frame["su_tree"] = False
        self.__scrollbar.pack_forget()

    self.__suser_panel = tk.Frame(self.__window)

    header_frame = tk.Frame(self.__suser_panel)

    header_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    label_user_info = tk.Label(header_frame, text=f"super user", font=("Arial", 16), fg="blue")
    label_user_info.pack(side=tk.RIGHT)

    label_welcome = tk.Label(self.__suser_panel, text="", font=("Arial", 16))
    label_welcome.pack(pady=50)

    # Пример элементов рабочей панели (можно добавить больше)
    # button_action1 = tk.Button(self.__admin_panel, text="Действие 1", command=lambda: messagebox.showinfo("Действие", "Выполнено действие 1"))
    button_action1 = tk.Button(self.__suser_panel, text="Получить список работников", command=load_table_user_data)
    button_action1.pack(pady=10)

    button_close_tables = tk.Button(self.__suser_panel, text="Закрыть панель", command=close_tables)
    button_close_tables.pack(pady=10)


    button_open_change_password = tk.Button(self.__suser_panel, text="Изменить пароль пользователя", command=self.__own_chg_passwd_window)
    button_open_change_password.pack(pady=10)


    button_logout = tk.Button(self.__suser_panel, text="Выход", command=self.__logout)
    button_logout.pack(pady=20)


# Создаём фрейм для таблицы
    table_frame = tk.Frame(self.__suser_panel)
    table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Создаём Treeview (таблицу) с столбцами
    self.__su_tree = ttk.Treeview(table_frame, columns=("login", "ФИО", "Должность", "Роль"), show="headings")

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
    self.__scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.__su_tree.yview)
    self.__su_tree.configure(yscroll=self.__scrollbar.set)



    # Кнопка для обновления таблицы
    # button_refresh = tk.Button(self.__admin_panel, text="Обновить таблицу", command=load_table_data)
    # button_refresh.pack(pady=10)

    # Загружаем данные при инициализации панели
    # self.load_table_data()





  def __init_user_panel(self) -> None:
    self.__user_panel = tk.Frame(self.__window)

    header_frame = tk.Frame(self.__user_panel)

    header_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    label_user_info = tk.Label(header_frame, text="user", font=("Arial", 14), fg="blue")
    label_user_info.pack(side=tk.RIGHT)

    label_welcome = tk.Label(self.__user_panel, text="", font=("Arial", 14))
    label_welcome.pack(pady=50)

    # Пример элементов рабочей панели (можно добавить больше)
    button_action1 = tk.Button(self.__user_panel, text="Действие 1", command=lambda: messagebox.showinfo("Действие", "Выполнено действие 1"))
    button_action1.pack(pady=10)

    button_open_change_password = tk.Button(self.__user_panel, text="Изменить пароль пользователя", command=self.__own_chg_passwd_window)
    button_open_change_password.pack(pady=10)

    button_logout = tk.Button(self.__user_panel, text="Выход", command=self.__logout)
    button_logout.pack(pady=20)


