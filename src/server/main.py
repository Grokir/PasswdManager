from logger import Logger
import server



def main():
  print(" >  Server now running...")
  server.run()
  print(" >  Server stopped!")


if __name__ == "__main__":
  main()