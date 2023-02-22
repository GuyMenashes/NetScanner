import re
import subprocess
import random
import time

def get_wifi_password():
    command=['netsh', 'wlan', 'show', 'interfaces']

    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
    output = output.stdout.decode(encoding='utf-8',errors='ignore')
    lines=output.split('\n')
    name=None
    for line in lines:
        if 'Profile' in line:
                name = line.split(':')[-1].strip()
    if not name:
        return
    
    command = 'for /f "skip=9 tokens=1,2 delims=:" %i in (\'netsh wlan show profiles\') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear'
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    txt = result.stdout.decode('utf-8').split('=======================================================================')
    net=None
    for i in range(len(txt)):
        if f'Profile {name} on interface' in txt[i]:
             net=txt[i+1]   
    if not net:
        return
    
    net=net.split('\n')
    password=None
    for line in net:
        if 'Key Content' in line:
             password=line.split(':')[-1].strip()
    
    if not password:
         return 'Open network, no password'
    
    return password

def is_good_pass(password):
    reasons=[]

    if (len(password)<12):
        reasons.append("Password should have at least 12 characters")
    
    if not re.search("[a-z]", password):
        reasons.append('Password should contain at least one lower character')

    if not re.search("[A-Z]", password):
        reasons.append('Password should contain at least one upper character')
    
    if not re.search("[0-9]", password):
        reasons.append('Password should contain at least one number')
    
    if not re.search("[!@#$%^&*()-_+=|\~><`:]" , password):
        reasons.append('Password should contain at least one of the special characters: !@#$%^&*()-_+=|\\~><`:')
    
    # Check for weak substrings
    weak_substrings = ['password', '123456', 'qwerty', 'admin', 'letmein']
    if any(substring in password.lower() for substring in weak_substrings):
        reasons.append('Password cannot contain any weak substirngs in it: password,123456,qwerty,admin,letmein')

    # Check for repeated characters
    repeated_chars_pattern = r'(\w)\1{2,}'
    if re.search(repeated_chars_pattern, password.lower()):
        reasons.append("Password cannot contain a repeated sequence of three or more consecutive identical characters")

    # Check for sequential characters
    sequential_chars_pattern = r'(123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)'
    if re.search(sequential_chars_pattern, password.lower()):
        reasons.append("Password cannot contain any three sequential characters")

    # Check for keyboard patterns
    keyboard_patterns = ['qwert', 'asdfg', 'zxcvb', 'poiuy', 'lkjhgf', 'mnbvc']
    if any(pattern in password.lower() for pattern in keyboard_patterns):
        reasons.append("Password cannot contain any of the keyboard patterns: qwert,asdfg,zxcvb,poiuy,lkjhgf,mnbvc")

    # Check for date patterns
    date_pattern = r'(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[012])(19|20)\d\d'
    if re.search(date_pattern, password):
        reasons.append("Password cannot contain a date")
    
    with open('weak_passwords.txt','r') as f:
        text=f.read()

    weak_passwords=text.split('\n')
    if password in weak_passwords:
        reasons.append("Password found in a collection of common passwords")

    return reasons

def generate_password():
    MAX_LEN = 12

    DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'] 
    LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                        'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                        'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                        'z']
    
    UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                        'I', 'J', 'K', 'M', 'N', 'O', 'P', 'Q',
                        'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                        'Z']
    
    SYMBOLS = ['@', '#', '$', '%', '=', ':', '?', '.', '/', '|', '~', '>',
            '*', '(', ')', '<']
    
    # combines all the character arrays above to form one array
    COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS

    password=''
    
    while len(is_good_pass(password))!=0:
        # randomly select at least one character from each character set above
        rand_digit = random.choice(DIGITS)
        rand_upper = random.choice(UPCASE_CHARACTERS)
        rand_lower = random.choice(LOCASE_CHARACTERS)
        rand_symbol = random.choice(SYMBOLS)

        password = rand_digit + rand_upper + rand_lower + rand_symbol
        
        for x in range(MAX_LEN - 4):
            password += random.choice(COMBINED_LIST)

            rotation_amount=random.randint(0,3)

            password=password[-rotation_amount:]+password[:-rotation_amount]
            
    return password