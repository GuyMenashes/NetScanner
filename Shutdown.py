import subprocess

def shutdown(ip):
    command = ['shutdown','/s','/m',r'\\'+ip,'/t','10','/c','"The computer will shutdown in 10 seconds"','/f']
    # Run the command and get the output
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    errors=output.stderr.decode(encoding='utf-8').removesuffix('\n')

    if errors!='':
        return errors

    return output.stdout.decode(encoding='utf-8',errors='ignore')

def restart(ip):
    command = ['shutdown','/r','/m',r'\\'+ip,'/t','10','/c','"The computer will shutdown in 10 seconds"','/f']
    # Run the command and get the output
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    errors=output.stderr.decode(encoding='utf-8').removesuffix('\n')
    
    if errors!='':
        return errors

    return output.stdout.decode(encoding='utf-8',errors='ignore')