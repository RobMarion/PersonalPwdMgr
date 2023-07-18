#!/usr/bin/python3
from PwdManager import PwdManager
import getpass
#import colorama  # just for fun
#from colorama import Fore


def cli_menu(pmgr):
    uname = input("Enter username: ")
    while True:
        print()
        #print(Fore.BLUE + "1. List all accounts")
        print("1. List all accounts")
        print("2. Get the password for an account")
        print("3. Add an account")
        print("4. Change a password")
        print("5. Delete an account")
        print("6. Add user")
        print("7. Delete user")
        print("8. [Q]uit")
        print()
        choice = input("Select one: ")
        if choice == "1":
            pmgr.get_account_names(uname)
        elif choice == "2":
            pmgr.get_password(uname)
        elif choice == "3":
            account_name = input("What account password would you like to add? ")
            pmgr.add_account(uname, account_name)
        elif choice == "4":
            account_name = input("What account password would you like to change? ")
            if pmgr.change_account_password(uname, account_name):
                print("Change successful")
            else:
                print("Change NOT successful")
        elif choice == "5":
            account_name = input("What account do you want to delete? ")
            opt = input(f"Are you sure you want to delete {account_name} N/y? ").casefold()
            if opt != "y":
                print("Ok. We won't delete it.")
            else:             
                if pmgr.delete_account(uname, account_name):
                    print(f"{account_name} deleted.")
                else:
                    print(f"{account_name} NOT deleted.")
        elif choice == "6":
            user = input("Enter user name: ")
            pwd = getpass.getpass("Password: ")
            if pwd == getpass.getpass("Confirm: "):
                print("adding ...")       
                pmgr.add_user_password(user,pwd)
        elif choice == "7":
            user = input("Enter user to be deleted: ")
            pwd = getpass.getpass("Password: ")
            pmgr.delete_user(user, pwd)
        elif choice == "8" or "Q" or "q":
            print("Thanks for stopping by.")
            return True
        else:
            ("Invalid selection. Try again")


def main():
    #colorama.init()
    pmgr = PwdManager()
    cli_menu(pmgr)



if __name__ == '__main__':
    main()



