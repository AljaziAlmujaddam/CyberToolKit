#!/usr/bin/env python3
"""CyberToolkit — main entry point (Part 6).

Displays the menu and launches each tool. Tool logic stays in its own module.
"""

from __future__ import annotations

import sys

import hash_calculator
import integrity_checker
import ip_information
import log_analyzer
import password_analyzer


def display_menu() -> None:
    """Show the CyberToolkit title and numbered options."""
    print()
    print("========================================")
    print("           CYBERTOOLKIT")
    print("========================================")
    print()
    print("1. Password Analyzer")
    print("2. Hash Calculator")
    print("3. File Integrity Checker")
    print("4. IP Information Tool")
    print("5. Log Analyzer")
    print("6. Exit")
    print()


def pause_for_menu(*, analysis_complete: bool = False) -> None:
    """Wait so the user can read the result before the menu returns."""
    print()
    if analysis_complete:
        print("Analysis complete.")
        print()
    input("Press Enter to return to the main menu...")


def handle_choice(choice: str) -> bool:
    """Run the selected tool. Return False when the program should exit."""
    text = choice.strip()

    if text == "" or not text.isdigit():
        print("Invalid input.")
        print("Please enter a number.")
        return True

    if text == "1":
        password_analyzer.main()
        pause_for_menu(analysis_complete=True)
        return True
    if text == "2":
        hash_calculator.main()
        pause_for_menu()
        return True
    if text == "3":
        integrity_checker.main()
        pause_for_menu()
        return True
    if text == "4":
        ip_information.main()
        pause_for_menu()
        return True
    if text == "5":
        log_analyzer.main()
        pause_for_menu()
        return True
    if text == "6":
        print()
        print("Thank you for using CyberToolkit.")
        print("Goodbye!")
        return False

    print("Invalid option.")
    print("Please select a number between 1 and 6.")
    return True


def main() -> None:
    """Loop the menu until the user chooses Exit."""
    print()
    print("CyberToolkit — educational cybersecurity tools.")
    print("For learning and defensive practice only.")

    while True:
        display_menu()
        choice = input("Select an option: ")
        if not handle_choice(choice):
            return


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
