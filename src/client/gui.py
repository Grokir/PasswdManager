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

  __activity: dict  = {
    "admin":      False,
    "super_user": False,
    "user" :      False,
    "guest":      False,
    "login":      False
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
    self.__init_user_panel()

  def run(self):
    # Запуск главного цикла
    self.__window.mainloop()

  def __change_frame(self, frame:str):
    self.__activity["login"] = False
    panel: tk.Frame = None

    match frame:
      case "admin":
        panel = self.__admin_panel
        self.__activity["admin"] = True
      case "super_user":
        panel = self.__suser_panel
        self.__activity["super_user"] = True
      case "user":
        panel = self.__user_panel
        self.__activity["user"] = True
      case "guest":
        panel = self.__guest_panel
        self.__activity["guest"] = True
    
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
        res_str:str = self.__receiver.POST(data)
        if res_str == "ok":
          res = self.__receiver.GET({"login": username})
          messagebox.showinfo("Успех", f"Вход выполнен для пользователя: {username}")
          self.__change_frame(res["role"])
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
    self.__activity["login"] = True
    panel: tk.Frame = None

    frame:str = ""

    for k in self.__activity.keys():
      if self.__activity[k]:
        frame = k
        break

    match frame:
      case "admin":
        panel = self.__admin_panel
        self.__activity["admin"] = False
      case "super_user":
        panel = self.__suser_panel
        self.__activity["super_user"] = False
      case "user":
        panel = self.__user_panel
        self.__activity["user"] = False
      case "guest":
        panel = self.__guest_panel
        self.__activity["guest"] = False

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
    special characters, and numbers} and password len = 8. 
    And returns False otherwise.
    """
    regex: str = "^[a-zA-Z" + str(punctuation) + "0-9]"
    pattern = re.compile(regex)
    return ( (pattern.search(password) is not None) and (len(password) >= 8) )
  
  def __init_login_panel(self) -> None:
    self.__activity["login"] = True

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

    # обновляем экран
    # self.__window.update()
    # self.__window.update_idletasks()

  def __init_admin_panel(self) -> None:

    def load_table_data():
      self.__receiver

      for item in self.__tree.get_children():
            self.__tree.delete(item)

      # Пример: получаем данные из Receiver (адаптируйте под ваш API)
      try:
        login:str = self.__entry_username.get()
        data_dict = self.__receiver.GET({"login": login})  # Предполагаем, что возвращает список словарей
        # Вставляем данные в таблицу
        self.__tree.insert("", tk.END, values=(
            data_dict["login"], 
            data_dict["full_name"], 
            data_dict["position"],
            data_dict["role"]
          )
        )
      except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось загрузить данные: {e}")

    self.__admin_panel = tk.Frame(self.__window)

    header_frame = tk.Frame(self.__admin_panel)

    header_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    label_user_info = tk.Label(header_frame, text=f"admin", font=("Arial", 10), fg="blue")
    label_user_info.pack(side=tk.RIGHT)

    label_welcome = tk.Label(self.__admin_panel, text="", font=("Arial", 14))
    label_welcome.pack(pady=50)

    # Пример элементов рабочей панели (можно добавить больше)
    # button_action1 = tk.Button(self.__admin_panel, text="Действие 1", command=lambda: messagebox.showinfo("Действие", "Выполнено действие 1"))
    button_action1 = tk.Button(self.__admin_panel, text="Действие 1", command=load_table_data)
    button_action1.pack(pady=10)

    # button_action2 = tk.Button(self.__admin_panel, text="Действие 2", command=lambda: messagebox.showinfo("Действие", "Выполнено действие 2"))
    # button_action2.pack(pady=10)

    button_logout = tk.Button(self.__admin_panel, text="Выход", command=self.__logout)
    button_logout.pack(pady=20)


# Создаём фрейм для таблицы
    table_frame = tk.Frame(self.__admin_panel)
    table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    # Создаём Treeview (таблицу) с столбцами
    self.__tree = ttk.Treeview(table_frame, columns=("login", "ФИО", "Должность", "Роль"), show="headings")
    self.__tree.pack(fill=tk.BOTH, expand=True)

    # Определяем заголовки столбцов
    self.__tree.heading("login", text="login")
    self.__tree.heading("ФИО", text="ФИО")
    self.__tree.heading("Должность", text="Должность")
    self.__tree.heading("Роль", text="Роль")

    # Устанавливаем ширину столбцов (опционально)
    self.__tree.column("login", width=50)
    self.__tree.column("ФИО", width=150)
    self.__tree.column("Должность", width=100)
    self.__tree.column("Роль", width=100)

    # Добавляем scrollbar для прокрутки
    scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.__tree.yview)
    self.__tree.configure(yscroll=scrollbar.set)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # Кнопка для обновления таблицы
    # button_refresh = tk.Button(self.__admin_panel, text="Обновить таблицу", command=load_table_data)
    # button_refresh.pack(pady=10)

    # Загружаем данные при инициализации панели
    # self.load_table_data()



  def __init_user_panel(self) -> None:
    self.__user_panel = tk.Frame(self.__window)

    header_frame = tk.Frame(self.__user_panel)

    header_frame.pack(side=tk.TOP, fill=tk.X, padx=10, pady=10)

    label_user_info = tk.Label(header_frame, text=f"admin", font=("Arial", 10), fg="blue")
    label_user_info.pack(side=tk.RIGHT)

    label_welcome = tk.Label(self.__user_panel, text="", font=("Arial", 14))
    label_welcome.pack(pady=50)

    # Пример элементов рабочей панели (можно добавить больше)
    button_action1 = tk.Button(self.__user_panel, text="Действие 1", command=lambda: messagebox.showinfo("Действие", "Выполнено действие 1"))
    button_action1.pack(pady=10)

    button_action2 = tk.Button(self.__user_panel, text="Действие 2", command=lambda: messagebox.showinfo("Действие", "Выполнено действие 2"))
    button_action2.pack(pady=10)

    button_logout = tk.Button(self.__user_panel, text="Выход", command=self.__logout)
    button_logout.pack(pady=20)


