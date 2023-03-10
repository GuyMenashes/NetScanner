import re
import subprocess
import random
import threading
import time

class password_tester():
    
    def __init__(self):
        self.password='Finding...'
        self.test_num=12
        self.level_dict={0:'c',1:'c',2:'c',3:'c',4:'c',5:'i',6:'i',7:'i',8:'r',9:'r',10:'i',11:'r'}
        threading.Thread(target=self.get_wifi_password).start()
        with open('all_words.txt','r') as f:
            text=f.read()

        self.words=text.split('\n')

    def get_wifi_password(self):
        command=['netsh', 'wlan', 'show', 'interfaces']

        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
        output = output.stdout.decode(encoding='utf-8',errors='ignore')
        lines=output.split('\n')
        name=None
        for line in lines:
            if 'Profile' in line:
                    name = line.split(':')[-1].strip()
        if not name:
            self.password='Failed to find password'
        
        command = 'for /f "skip=9 tokens=1,2 delims=:" %i in (\'netsh wlan show profiles\') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear'
        result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        txt = result.stdout.decode('utf-8').split('=======================================================================')
        net=None
        for i in range(len(txt)):
            if f'Profile {name} on interface' in txt[i]:
                net=txt[i+1]   
        if not net:
            self.password='Failed to find password'
            return
        
        net=net.split('\n')
        password=None
        for line in net:
            if 'Key Content' in line:
                password=line.split(':')[-1].strip()
        
        if not password:
            self.password= 'Open network, no password'
        
        self.password= password

    def is_good_pass(self,password):
        tests=[1]*self.test_num

        if (len(password)<12):
            tests[0]=0
        
        if not re.search("[a-z]", password):
            tests[1]=0

        if not re.search("[A-Z]", password):
            tests[2]=0
        
        if not re.search("[0-9]", password):
            tests[3]=0
        
        if  bool(re.match(r'^[a-zA-Z0-9]+$', password)):
            tests[4]=0
        
        # Check for weak substrings
        weak_substrings = ['password', '123456', 'qwerty', 'admin', 'letmein']
        if any(substring in password.lower() for substring in weak_substrings):
            tests[5]=0

        # Check for repeated characters
        repeated_chars_pattern = r'(\w)\1{2,}'
        if re.search(repeated_chars_pattern, password.lower()):
            tests[6]=0

        # Check for sequential characters
        sequential_chars_pattern = r'(123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)'
        if re.search(sequential_chars_pattern, password.lower()):
            tests[7]=0

        # Check for keyboard patterns
        keyboard_patterns = ['qwert', 'asdfg', 'zxcvb', 'poiuy', 'lkjhgf', 'mnbvc']
        if any(pattern in password.lower() for pattern in keyboard_patterns):
            tests[8]=0

        # Check for date patterns
        date_pattern = r'(0[1-9]|[12][0-9]|3[01])(0[1-9]|1[012])(19|20)\d\d'
        if re.search(date_pattern, password):
            tests[9]=0
        
        with open('weak_passwords.txt','r') as f:
            text=f.read()

        weak_passwords=text.split('\n')
        if password in weak_passwords:
            tests[10]=0

        for word in self.words:
            if word in password:
                tests[11]=0
                break

        return tests

    def generate_password(self):
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
        
        SYMBOLS = ['@', '#', '$', '%', '=', '?', '.', '/', '|', '~', '>',
                '*', '(', ')', '<']
        
        # combines all the character arrays above to form one array
        COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS

        password=''
        
        while 0 in self.is_good_pass(password):
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