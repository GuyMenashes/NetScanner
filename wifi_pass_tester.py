# Importing required libraries
import subprocess
import random
import threading
import re

class password_tester():
    
    def __init__(self):
        self.password='Finding...'
        self.test_num=12
        
        # Dictionary mapping password strength levels to test types
        self.level_dict={0:'c',1:'c',2:'c',3:'c',4:'c',5:'i',6:'i',7:'i',8:'r',9:'r',10:'i',11:'r'}
        
        # Start a new thread to get the wifi password
        threading.Thread(target=self.get_wifi_password).start()
        
        # Load dictionary words from file
        with open('all_words.txt','r') as f:
            text=f.read()
        self.words=text.split('\n')

    def get_wifi_password(self):
        # Use netsh command to get wifi interface information
        command=['netsh', 'wlan', 'show', 'interfaces']
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
        output = output.stdout.decode(encoding='utf-8',errors='ignore')
        lines=output.split('\n')
        
        # Extract the wifi profile name from the output
        name=None
        for line in lines:
            if 'Profile' in line:
                    name = line.split(':')[-1].strip()
        
        # Return if no wifi profile found
        if not name:
            self.password='Failed to find password'
            return
        
        # Use netsh command to get wifi profile information
        command = f'netsh wlan show profile {name} key=clear'
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        txt = result.stdout.decode('utf-8')
        
        # Return if wifi profile not found
        if 'not found' in txt:
            self.password= 'Failed to find password'
            return
        
        txt=txt.split('\n')
        password=None
        
        # Extract the wifi password from the output
        for line in txt:
            if 'Key Content' in line:
                password=line.split(':')[-1].strip()
        
        # If no wifi password found, assume it's an open network
        if not password:
            password= 'Open network, no password'
        
        self.password= password

    def is_good_pass(self, password):
        # Create a list to keep track of the results of all the tests
        tests = [1] * self.test_num

        # Check the length of the password and mark test 0 as failed if it's less than 12 characters
        if len(password) < 12:
            tests[0] = 0

        # Check if the password contains at least one lowercase letter and mark test 1 as failed if it doesn't
        if not re.search("[a-z]", password):
            tests[1] = 0

        # Check if the password contains at least one uppercase letter and mark test 2 as failed if it doesn't
        if not re.search("[A-Z]", password):
            tests[2] = 0

        # Check if the password contains at least one digit and mark test 3 as failed if it doesn't
        if not re.search("[0-9]", password):
            tests[3] = 0

        # Check if the password consists of only alphanumeric characters and mark test 4 as failed if it doesn't
        if bool(re.match(r'^[a-zA-Z0-9]+$', password)):
            tests[4] = 0

        # Check if the password contains any weak substrings and mark test 5 as failed if it does
        weak_substrings = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if any(substring in password.lower() for substring in weak_substrings):
            tests[5] = 0

        # Check if the password contains any repeated characters and mark test 6 as failed if it does
        repeated_chars_pattern = r'(\w)\1{2,}'
        if re.search(repeated_chars_pattern, password.lower()):
            tests[6] = 0

        # Check if the password contains any sequential characters and mark test 7 as failed if it does
        sequential_chars_pattern = r'(123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)'
        if re.search(sequential_chars_pattern, password.lower()):
            tests[7] = 0

        # Check if the password contains any keyboard patterns and mark test 8 as failed if it does
        keyboard_patterns = ['qwert', 'asdfg', 'zxcvb', 'poiuy', 'lkjhgf', 'mnbvc']
        if any(pattern in password.lower() for pattern in keyboard_patterns):
            tests[8] = 0

        # Check if the password matches any date patterns and mark test 9 as failed if it does
        date_pattern = r'(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[012])(19|20)\d\d'
        if re.search(date_pattern, password):
            tests[9] = 0

        # Check if the password is in the list of weak passwords and mark test 10 as failed if it is
        with open('weak_passwords.txt', 'r') as f:
            text = f.read()
        weak_passwords = text.split('\n')
        if password in weak_passwords:
            tests[10] = 0

        # Check if the password contains any of the words in the all words file
        for word in self.words:
            if word in password:
                tests[11]=0
                break

        return tests

    def generate_password(self):
        MAX_LEN = 12

        # Define character sets
        DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'] 
        LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                            'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
                            'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
                            'z']
        UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                            'I', 'J', 'K', 'M', 'N', 'O', 'P', 'Q',
                            'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
                            'Z']
        SYMBOLS = ['@', '#', '$', '%', '=', '?', '.', '/', '|', '~', '>',
                '*', '(', ')', '<']

        # Combine all the character arrays above to form one array
        COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS

        # Initialize an empty password string
        password=''

        # While the generated password does not pass all the tests
        while 0 in self.is_good_pass(password):

            # Randomly select at least one character from each character set
            rand_digit = random.choice(DIGITS)
            rand_upper = random.choice(UPCASE_CHARACTERS)
            rand_lower = random.choice(LOCASE_CHARACTERS)
            rand_symbol = random.choice(SYMBOLS)

            # Add the randomly selected characters to the password string
            password = rand_digit + rand_upper + rand_lower + rand_symbol

            # Add random characters from the combined list to the password string
            for x in range(MAX_LEN - 4):
                password += random.choice(COMBINED_LIST)

                # Rotate the password by a random amount
                rotation_amount=random.randint(0,3)
                password=password[-rotation_amount:]+password[:-rotation_amount]

        # Return the generated password
        return password