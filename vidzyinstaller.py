import os

os.system("clear")

print(" _   _ _     _           ")
print("| | | (_)   | |          ")
print("| | | |_  __| |_____   _ ")
print("| | | | |/ _` |_  / | | |")
print("\ \_/ / | (_| |/ /| |_| |")
print(" \___/|_|\__,_/___|\__, |")
print("                    __/ |")
print("                   |___/ ")
print("        Installer        ")

print("\n")

i = input(
    "Vidzy installer will guide you through the installation of Vidzy on your server. Note: Vidzy installer is in alpha and may not work properly. Press enter to continue"
)

os.system("clear")

print("Please confirm that you have the following packages installed:\nPython3\nPip (python package manager)\n\n")
i = input("(Y/n) ")

if i.lower() == "n":
    exit()

os.system("clear")

os.system("pip install -r requirements.txt")

os.system("clear")

os.system("cp .env.sample .env")
i = input("What editor would you like to use to configure .env? (nano/vi/custom) ")
if i == "nano":
    os.system("nano .env")
elif i == "vi":
    os.system("vi .env")
elif i == "custom":
    j = input("What editor would you like to use to configure .env? ")
    os.system(j + " .env")

os.system("clear")

i = input("What mysql database should Vidzy use?")
os.system("mysql " + i + " < mysql-dump/MYSQL_DATABASE.sql")

print("If above command fails, than just source VIDZY_DIR/mysql-dump/MYSQL_DATABASE.sql")

print("\n\n\nVidzy Installation Completed!")