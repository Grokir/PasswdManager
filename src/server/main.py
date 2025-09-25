from logger import Logger

def main():
  log: Logger = Logger("./")
  log.send("test message!")


if __name__ == "__main__":
  main()