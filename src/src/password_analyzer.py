#!/usr/bin/env python3
"""CyberToolkit — Password Analyzer (Part 1, Step 1).

This first version only:
1. Asks the user to enter a password
2. Calculates how many characters it has
3. Displays the length

The password stays in memory for this run only. It is not saved,
logged, or sent anywhere.
"""

import getpass


def get_password() -> str:
    """Ask the user for a password without echoing it on the screen."""
    return getpass.getpass("Enter a password: ")


def password_length(password: str) -> int:
    """Return the number of characters in the password."""
    return len(password)


def main() -> None:
    print()
    print("========================================")
    print("        PASSWORD ANALYZER")
    print("========================================")
    print()

    password = get_password()
    length = password_length(password)

    print()
    print("Password Analysis")
    print("-----------------")
    print(f"Length: {length}")


if __name__ == "__main__":
    main()
