import string
import random
import requests
banner = """

   _____            _       _  _____                          
  / ____|          (_)     | |/ ____|                         
 | (___   ___   ___ _  __ _| | (___   ___  ___ _   _ _ __ ___ 
  \___ \ / _ \ / __| |/ _` | |\___ \ / _ \/ __| | | | '__/ _ \
  ____) | (_) | (__| | (_| | |____) |  __/ (__| |_| | | |  __/
 |_____/ \___/ \___|_|\__,_|_|_____/ \___|\___|\__,_|_|  \___|
  A tool to evaluate the strength of your passwords and create custom encryption algorithms to enhance your password security
  Github :https://github.com/TheNewAttacker64
"""
__author__ = "ThenewAttacker64"
def password_strength(password):
    score = 0
    length = len(password)
    if length >= 8:
        score += 1
    if any(c in string.ascii_lowercase for c in password):
        score += 1
    if any(c in string.ascii_uppercase for c in password):
        score += 1
    if any(c in string.digits for c in password):
        score += 1
    if any(c in string.punctuation for c in password):
        score += 1
    return score

def brute_force_time(password):
    characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
    combinations = pow(len(characters), len(password))
    attempts_per_second = 1000000000 # assuming a modern CPU can make a billion attempts per second
    seconds = combinations / attempts_per_second
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24
    years = days / 365
    return years, days, hours, minutes, seconds

def encrypt_password(password, encryption_dict):
    encrypted_password = ""
    for c in password:
        if c in encryption_dict:
            encrypted_password += encryption_dict[c]
        else:
            encrypted_password += c
    return encrypted_password
def example():
    example = """
Example{
    password = mypassword
    Enter a character to encrypt (or enter 'done' if finished): a
    Enter the replacement character for 'a': @
    Enter a character to encrypt (or enter 'done' if finished): t
    Enter the replacement character for 't': +
    Enter a character to encrypt (or enter 'done' if finished): done

Your encrypted password is: my+p@ssw+rd
Encryption technique:
'a' -> '@'
't' -> '+'

}
"""

    return example
def avast(email):
    print("[*] Checking Avast API")
    url = 'https://bodyguard.avast.com/v1/web/email/one-time-check'
    payload = {'email': email}

    headers = {
        'authority': 'bodyguard.avast.com',
        'accept': 'application/json, text/plain, */*',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
        'content-length': '46',
        'content-type': 'application/json;charset=UTF-8',
        'origin': 'https://www.avast.com',
        'referer': 'https://www.avast.com/',
        'sec-ch-ua': '"Google Chrome";v="111", "Not(A:Brand";v="8", "Chromium";v="111"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': ''
    }

    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/59.0.3071.115 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
    ]
    headers['user-agent'] = random.choice(user_agents)

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code == 200:
        data = response.json()

        if data['value']['leaks_found']:
            print("[-] Leaks found in Avast API! ")
            print("""
            What should you Do 
                  change your email password
            
            """)
        else:
            print("[+] Good No leaks found.")
    else:
        print("Error:", response.status_code)
def main():
    print(banner)
    menu = """
1)  Check Password Security Status
2)  Secure Your Password Make Customer Encryption algorithm to your password 
3)  check if you have been pwned
99) exit
    """
    print(menu)
    choose = int(input("Option:"))
    if choose == 1:
        password = input("Enter your password: ")

        score = password_strength(password)
        print(f"Your password strength score is {score}/5.")
        time_to_crack_years, time_to_crack_days, time_to_crack_hours, time_to_crack_minutes, time_to_crack_seconds = brute_force_time(
            password)

        print(
            f"It would take approximately {time_to_crack_years:.2f} years ({time_to_crack_days:.2f} days, {time_to_crack_hours:.2f} hours, or {time_to_crack_minutes:.2f} minutes) to crack your password using a brute-force attack.")
        main()
    elif choose == 2:
        print(example())
        password = input("Enter your password: ")

        encryption_dict = {}
        while True:
            key = input("Enter a character to encrypt (or enter 'done' if finished): ")
            if key == "done":
                break
            value = input(f"Enter the replacement character for '{key}': ")
            encryption_dict[key] = value
        encrypted_password = encrypt_password(password, encryption_dict)
        print(f"Your encrypted password is: {encrypted_password}")


        filename = "encryption_config.txt"
        with open(filename, "w") as file:
            for key, value in encryption_dict.items():
                file.write(f"{key}={value}\n")
            file.write(f"Instructions for decrypting:\n"
                       f"1. Replace each encrypted character with its corresponding original character as specified in the file.\n"
                       f"2. Enter the decrypted password to access your file.\n")
        print(f"Encryption configuration written to '{filename}'.")
        main()
    elif choose == 3:
        email = input("Enter your email:")
        avast(email)
        main()
    elif  choose == 99:
        print("Bye :)")
        exit(0)
    else:
        print("[-] Invalid option")
        main()

main()


