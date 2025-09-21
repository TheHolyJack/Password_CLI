import argparse
import hashlib
import requests
import re
import sys
import math
import csv
from colorama import init, Fore, Style


init(autoreset=True)



def check_pwned(password: str) -> int:
    """
    Checks if a given password has been exposed in data breaches using the "Have I Been Pwned" API.
    This function computes the SHA-1 hash of the password, queries the HIBP API with the first
    five characters of the hash, and checks the response for the suffix match. If a match is
    found, it returns the count of times the password has been exposed. Otherwise, it returns 0.

    :param password: The password to check for exposure in data breaches, provided as a string.
    :type password: str
    :return: The number of times the password was found in data breaches, or 0 if not found.
    :rtype: int
    :raises RuntimeError: If there is an error fetching data from the "Have I Been Pwned" API.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError("Error fetching from HIBP API")

    for line in res.text.splitlines():
        h, count = line.split(":")
        if h == suffix:
            return int(count)
    return 0

def password_strength(password: str) -> tuple[str, float]:
    """
    Calculates the password strength based on entropy and character set size.

    The function evaluates the complexity of a given password by analyzing
    the combination of character types in the password such as lowercase letters,
    uppercase letters, digits, and special symbols. It then computes the entropy
    to determine its strength.

    :param password: The password whose strength is to be evaluated.
    :type password: str
    :return: A tuple containing the strength rating of the password as a string
        ("Very Weak", "Weak", "Reasonable", "Strong", "Very Strong") and the
        calculated entropy as a float.
    :rtype: tuple[str, float]
    """
    charset_size = 0

    if re.search(r"[a-z]", password):
        charset_size += 26
    if re.search(r"[A-Z]", password):
        charset_size += 26
    if re.search(r"[0-9]", password):
        charset_size += 10
    if re.search(r"[@$!%*?&]", password):
        charset_size += len("@$!%*?&")
    if re.search(r"[^a-zA-Z0-9@$!%*?&]", password):
        # catch any other symbols not in the above list
        charset_size += 32

    if charset_size == 0:
        return "Invalid", 0.0

    entropy = len(password) * math.log2(charset_size)

    if entropy < 28:
        rating = (Fore.RED + "Very Weak" + Style.RESET_ALL)
    elif entropy < 36:
        rating = (Fore.RED + "Weak" + Style.RESET_ALL)
    elif entropy < 60:
        rating = (Fore.YELLOW + "Reasonable" + Style.RESET_ALL)
    elif entropy < 128:
        rating = (Fore.BLUE + "Strong" + Style.RESET_ALL)
    else:
        rating = (Fore.GREEN + "Very Strong" + + Style.RESET_ALL)

    return rating, entropy


def process_csv(input_file: str, output_file: str):


    try:
        with open(input_file, newline="", encoding="utf-8") as csvfile:
            reader = csv.DictReader(csvfile)
            if 'password' not in reader.fieldnames:
                print("Error: CSV file does not contain a 'password' column.")
                return

            with open(output_file, "w", newline="", encoding="utf-8") as out_csv:
                fieldnames = ["password", "strength", "entropy", "breach_count"]
                writer = csv.DictWriter(out_csv, fieldnames=fieldnames)
                writer.writeheader()

                for i, row in enumerate(reader, start=1):
                    password = row.get("password")
                    if not password:
                        print(f"Row {i}: Skipping Empty Password")
                        continue

                    password = str(password)
                    rating, entropy = password_strength(password)
                    try:
                        entropy = float(entropy)
                    except (ValueError, TypeError):
                        entropy = 0.0

                    try:
                        count = check_pwned(password)
                    except Exception as e:
                        print(f"Row {i}: Error checking breaches: {e}")
                        count = -1

                    writer.writerow({
                        'password': password,
                        'strength': rating,
                        'entropy': entropy,
                        'breach_count': count,
                    })

                    print(f"Row {i} " + Fore.GREEN + "processed" + Style.RESET_ALL + f": {password} -> {rating}, Entropy: {entropy:.2f}, Breach Count: {count}")

            print(f"CSV file processed successfully: {input_file} -> {output_file}")
    except FileNotFoundError:
        print(f"Error: File not found: {input_file}")
    except Exception as e:
        print(f"Error processing CSV file: {e}")




def main():
    """
    The program checks the strength of a given password and compares it against known data breaches. It evaluates the
    entropy of the password, providing a rating based on its strength. Additionally, it checks if the password
    exists in publicly known breaches, aiding users to improve their password security practices.

    The script expects a single password input through the command-line argument. If no password or an incorrect number of
    arguments are provided, the program displays usage information and terminates.

    Processes:
    - Evaluates password strength based on entropy.
    - Provides an explanation of entropy levels and how they relate to password security.
    - Checks the password against a database of known breaches, offering feedback on whether the password has been
      compromised.

    :raises SystemExit: If the number of provided arguments is incorrect.
    """

    parser = argparse.ArgumentParser(description="Password Strength & Breach Checker")
    parser.add_argument("-i", "--input", help="Password to check")
    parser.add_argument("-o", "--output", help="Output file name.")
    parser.add_argument("-c", "--csv", help="CSV file name.")
    args = parser.parse_args()

    if args.input and args.csv:
        print("Error. Please do not use both input and csv arguments.")


    if args.input:
        password = args.input
        rating, entropy = password_strength(password)
        print("\nℹ️ Entropy is a measure of unpredictability:")
        print("- <28 bits   → Very Weak (easy to brute-force instantly)")
        print("- 28–35 bits → Weak (could be cracked quickly)")
        print("- 36–59 bits → Reasonable (okay, but not great)")
        print("- 60–127 bits → Strong (safe for most use cases)")
        print("- 128+ bits  → Very Strong (virtually uncrackable)")
        print(f"🔐 Password Strength: {rating} (Entropy: {entropy:.2f} bits)")

        try:
            count = check_pwned(password)
            if count:
                print(Fore.RED + f"⚠ Found in {count} breaches! Choose a different password." + Style.RESET_ALL)
            else:
                print(Fore.GREEN + "✅ Not found in known breaches." + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Error checking breaches: {e}" + Style.RESET_ALL)

        try:
            count = check_pwned(password)
            if count:
                print(f"\n⚠️  Found in {count} breaches! Choose a different password.")
            else:
                print("\n✅ Not found in known breaches.")
        except Exception as e:
            print(f"Error checking breaches: {e}")
    elif args.csv:
        input_file = args.csv
        output_file = args.output or f"{input_file.rsplit('.', 1)[0]}-results.csv"
        process_csv(input_file, output_file)
    else:
        print(Fore.RED + "Error: Missing input. Please provide a password -i or CSV file. -c" + Style.RESET_ALL)