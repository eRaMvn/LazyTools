import glob
import os
import shutil
import json
import argparse
import sys

parser = argparse.ArgumentParser(description='Program created by eRaMvn. This program creates a new folder with the name specified and copied all files that start with that name into that folder.', 
    usage='%(prog)s folder_name')
parser.add_argument('folder_name', help="specify the name of folder to create")

args = parser.parse_args()
name = args.folder_name

# Make directory with name specified, if the directory exists, ask for confirmation, otherwise quit program
while True:
    try:
        os.mkdir(f"./{name}")
        break
    except OSError:
        print(f"'{name}' directory already exists!")
        choice = input("Do you want to remove that folder? (Y/N): ")
        if choice == "Y" or choice == "y":
            os.removedirs(f"./{name}")
        elif choice == "N" or choice == "n":
            print('Please try again later!')
            sys.exit()
        else:
            print('Unrecognized input')

# Match files that start with that directory
files = glob.glob(f'./{name}*.txt')

# Move files into the folder
for file in files:
    destination = f"./{name}/{file}"
    shutil.move(file, destination)
    print(f"moved '{file}' to '{destination}'")