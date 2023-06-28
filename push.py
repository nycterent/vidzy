import os

commit_title = input("Enter Commit Title: ")

os.system("git add * && git commit -m \"" + commit_title + "\" && git push -u origin main")