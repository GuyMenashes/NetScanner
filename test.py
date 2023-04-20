import subprocess
import os,time,threading

a=time.time()
threading.Thread(target=lambda:os.system(f'start cmd /k "mode con: cols=200 lines=1000 && netstat -a"')).start()
print(time.time()-a)