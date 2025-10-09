from sys import path as sys_path
sys_path.append("App")

from App.gui import GUI_APP


def main():
  app: GUI_APP = GUI_APP()
  app.run()


if __name__ == "__main__":
  main()