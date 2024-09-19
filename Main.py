import Password_Generation as Generation
import Storage


def main():
    print("Welcome to the Password Manager")
    Storage.initialize_db()
    #master_password = 'hello123'

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
        print("5. Test")

        choice = input("Select an option: ")

        if choice == "1":
            service = input("Enter service name: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            Storage.store_password(service, username, password, master_password)
            print("Password stored successfully!")

        elif choice == "2":
            services = Storage.display_services()
            print(services)
            id = input("Enter the ID of the service you want to choose: ")
            username, decrypted_password = Storage.retrieve_password(id, master_password)


            print(f"username: {username}\npassword: {decrypted_password}")
            print("1. Change password")
            print("2. Delete password")
            print("3. Go to Main Menu")
            choice = input("Select an option: ")



        elif choice == "3":
            length = int(input("Enter password length: "))
            password = Generation.generate_password(length)
            print(f"Generated password: {password}")

        elif choice == "4":
            old_master_password = input("Enter your current master password: ")
            master_password = Storage.change_master_password(old_master_password)

        elif choice == "5":
            print("Exiting...")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()