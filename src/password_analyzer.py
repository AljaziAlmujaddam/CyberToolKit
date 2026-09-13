#!/usr/bin/env python3
"""CyberToolkit — Password Analyzer (Part 1).

Checks length and character classes locally, then classifies strength.
The password stays in memory for this run only. It is not saved,
logged, printed, or sent anywhere.
"""

from __future__ import annotations

import getpass
import string
import sys

SPECIAL_CHARACTERS = set(string.punctuation)

STRENGTH_VERY_WEAK = "Very Weak"
STRENGTH_WEAK = "Weak"
STRENGTH_MEDIUM = "Medium"
STRENGTH_STRONG = "Strong"


def get_password() -> str:
    """Ask the user for a password without echoing it on the screen."""
    return getpass.getpass("Enter a password: ")


def password_length(password: str) -> int:
    """Return the number of characters in the password."""
    return len(password)


def has_uppercase(password: str) -> bool:
    """Return True if the password contains at least one uppercase letter."""
    return any(character.isupper() for character in password)


def has_lowercase(password: str) -> bool:
    """Return True if the password contains at least one lowercase letter."""
    return any(character.islower() for character in password)


def has_digit(password: str) -> bool:
    """Return True if the password contains at least one digit."""
    return any(character.isdigit() for character in password)


def has_special(password: str) -> bool:
    """Return True if the password contains at least one punctuation character."""
    return any(character in SPECIAL_CHARACTERS for character in password)


def analyze_password(password: str) -> dict:
    """Return length, character-class flags, strength, and suggestions."""
    length = password_length(password)
    classes = {
        "uppercase": has_uppercase(password),
        "lowercase": has_lowercase(password),
        "digit": has_digit(password),
        "special": has_special(password),
    }
    return {
        "length": length,
        **classes,
        "class_count": sum(classes.values()),
        "strength": classify_strength(length, classes),
        "suggestions": password_suggestions(length, classes),
    }


def classify_strength(length: int, classes: dict[str, bool]) -> str:
    """Classify strength from length and character-class variety.

    This is an educational rule set, not a substitute for a password meter
    that checks common passwords or leaked credentials.
    """
    class_count = sum(bool(value) for value in classes.values())

    if length == 0:
        return STRENGTH_VERY_WEAK
    if length < 8 or class_count <= 1:
        return STRENGTH_VERY_WEAK
    if length < 12 or class_count == 2:
        return STRENGTH_WEAK
    if class_count == 3:
        return STRENGTH_MEDIUM
    return STRENGTH_STRONG


def password_suggestions(length: int, classes: dict[str, bool]) -> list[str]:
    """Return short, local tips. Never includes the password itself."""
    tips: list[str] = []
    if length < 8:
        tips.append("Use at least 8 characters.")
    elif length < 12:
        tips.append("A length of 12 or more is stronger.")
    if not classes.get("uppercase"):
        tips.append("Add at least one uppercase letter.")
    if not classes.get("lowercase"):
        tips.append("Add at least one lowercase letter.")
    if not classes.get("digit"):
        tips.append("Add at least one number.")
    if not classes.get("special"):
        tips.append("Add at least one special character.")
    if not tips:
        tips.append("Variety and length look good for this simple checker.")
    return tips


def format_analysis(result: dict) -> str:
    """Build the on-screen report. Does not include the password."""
    yes_no = {True: "Yes", False: "No"}
    lines = [
        "Password Analysis",
        "-----------------",
        f"Length: {result['length']}",
        "",
        "Character classes",
        f"Uppercase letters : {yes_no[result['uppercase']]}",
        f"Lowercase letters : {yes_no[result['lowercase']]}",
        f"Numbers           : {yes_no[result['digit']]}",
        f"Special characters: {yes_no[result['special']]}",
        "",
        f"Strength: {result['strength']}",
        "",
        "Suggestions",
    ]
    for tip in result["suggestions"]:
        lines.append(f"- {tip}")
    lines.append("")
    lines.append("The password was not stored or sent anywhere.")
    return "\n".join(lines)


def main() -> None:
    print()
    print("========================================")
    print("        PASSWORD ANALYZER")
    print("========================================")
    print()
    print("Educational note:")
    print("This tool only checks length and character types.")
    print("It does not check leaked passwords or common words.")
    print()

    password = get_password()
    result = analyze_password(password)

    print()
    print(format_analysis(result))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(0)
