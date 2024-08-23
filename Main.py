import Encrypt_Decrypt
import Password_Generation as generation


def main():
    print("Welcome to the Password Manager")

    master_password = input("Enter your master password: ")

    while True:
        print("\nOptions:")
        print("1. Store a new password")
        print("2. Retrieve a password")
        print("3. Generate a random password")
        print("4. Exit")

        choice = input("Select an option: ")

        if choice == "1":
            service = input("Enter service name: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            #store_password(service, username, password, master_password)
            print("Password stored successfully!")

        elif choice == "2":
            service = input("Enter service name: ")
            try:
                username, password = 500,200#retrieve_password(service, master_password)
                print(f"Username: {username}")
                print(f"Password: {password}")
            except ValueError as e:
                print(e)

        elif choice == "3":
            length = int(input("Enter password length: "))
            password = generation.generate_password(length)
            print(f"Generated password: {password}")

        elif choice == "4":
            print("Exiting...")
            break

        else:
            print("Invalid option. Please try again.")

if __name__ == "__main__":
    main()