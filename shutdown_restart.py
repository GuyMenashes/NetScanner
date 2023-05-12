# Importing required libraries
import subprocess

def shutdown(out,ip,time,message):
    # Construct the command to shutdown
    command = ['shutdown','/s','/m',r'\\'+ip,'/t',time,'/c',message,'/f']
    
    # Run the command and get the output
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Check for errors in the stderr
    errors=output.stderr.decode(encoding='utf-8').removesuffix('\n')

    # If there are errors, append them to the output list and return
    if errors!='':
        out.append(errors)
        return
    
    # Get the stdout of the command
    result=output.stdout.decode(encoding='utf-8',errors='ignore')

    # If the stdout is empty, construct a success message
    if result=='':
        result=f"Succes! {ip} will shutdown in {time} seconds"

    # If the stdout is too long, construct an error message
    if len(result)>300:
        result="Error! Could be caused by invalid input!"

    # Append the result to the output list
    out.append(result)


def restart(out,ip,time,message):
    # Construct the command to restart
    command = ['shutdown','/r','/m',r'\\'+ip,'/t',time,'/c',message,'/f']
    
    # Run the command and get the output
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # Check for errors in the stderr
    errors=output.stderr.decode(encoding='utf-8').removesuffix('\n')
    
    # If there are errors, append them to the output list and return
    if errors!='':
        out.append(errors)
        return

    # Get the stdout of the command
    result=output.stdout.decode(encoding='utf-8',errors='ignore')

    # If the stdout is empty, construct a success message
    if result=='':
        result=f"Succes! {ip} will restart in {time} seconds"

    # If the stdout is too long, construct an error message
    if len(result)>300:
        result="Error! Could be caused by invalid input!"

    # Append the result to the output list
    out.append(result)