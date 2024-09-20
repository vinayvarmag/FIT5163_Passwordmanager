from tkinter import Menu

import Encrypt_Decrypt
import Password_Generation as Generation
import Storage


def main():
    print("Welcome to the Password Manager")
    Storage.initialize_db()

    master_password = Storage.verify_master_password_on_login()

    if master_password is None:
        return


    while True:
        print("\nOptions:")
        print("1. Store a new password")
        print("2. Retrieve a password")
        print("3. Generate a random password")
        print("4. Change Master Password and authenticator")
        print("5. Exit")

        choice = input("Select an option: ")

        if choice == "1":
            service = input("Enter service name: ")
            username = input("Enter username: ")
            while True:
                print("Press 1 to generate a password or enter the password you want to store")
                print("Press 0 to go back to Main Menu")
                password = input("Enter password: ")
                if password == "1":
                    length = int(input("Enter length of the password: "))
                    password = Generation.generate_password(length)
                    print(password)
                    confirm = input("Press Y if you want to store the password or N to re-enter password: ")
                    if confirm == "Y":
                        Storage.store_password(service, username, password, master_password)
                        break
                    elif confirm == "N":
                        print("try again")
                elif password == 0:
                    break
                elif password:
                    confirm = input("Press Y if you want to store the password or N to re-enter password: ")
                    if confirm == "Y":
                        Storage.store_password(service, username, password, master_password)
                        break
                    elif confirm == "N":
                        print("try again")
                    elif confirm == "0":
                        break


        elif choice == "2":
            services = Storage.display_services()
            while True:
                print(services)
                print("Press 0 to go back to Main Menu")
                id = input("Enter the ID of the service you want to choose: ")
                username, decrypted_password = Storage.retrieve_password(id, master_password)
                if username:
                    print(f"username: {username}\npassword: {decrypted_password}")
                    print("1. Change password")
                    print("2. Delete Service")
                    print("0. Go to Main Menu")
                    confirm = input("Select an option: ")
                    if confirm == "1":
                        changed_password = input("Enter new password: ")
                        confirmed_password = input ("Confirm new password:")
                        if changed_password == confirmed_password:
                            Storage.change_password(id, changed_password, master_password)
                        else:
                            print("Passwords do not match")

                    elif confirm == "2":
                        delete_service = input("Are you sure you want to delete this service? (Y/N): ")
                        if delete_service == "Y":
                            Storage.delete_service(id)
                            services = Storage.display_services()
                        elif delete_service == "N":
                            break
                        else:
                            print("Invalid option")
                    elif confirm == "0":
                        break
                else:
                    break



        elif choice == "3":
            length = int(input("Enter password length: "))
            password = Generation.generate_password(length)
            print(f"Generated password: {password}")

        elif choice == "4":
            old_master_password = input("Enter your current master password: ")
            master_password = Storage.change_master_password(old_master_password)

        elif choice == "5":
            print("Exiting....")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()