import subprocess

def shutdown(out,ip,time,message):
    command = ['shutdown','/s','/m',r'\\'+ip,'/t',time,'/c',message,'/f']
    # Run the command and get the output
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    errors=output.stderr.decode(encoding='utf-8').removesuffix('\n')

    if errors!='':
        out.append(errors)
        return
    
    result=output.stdout.decode(encoding='utf-8',errors='ignore')

    if result=='':
        result=f"Succes! {ip} will shutdown in {time} seconds"

    if len(result)>300:
        result="Error! Could be caused by invalid input!"

    out.append(result)


def restart(out,ip,time,message):
    command = ['shutdown','/r','/m',r'\\'+ip,'/t',time,'/c',message,'/f']
    # Run the command and get the output
    output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    errors=output.stderr.decode(encoding='utf-8').removesuffix('\n')
    
    if errors!='':
        out.append(errors)
        return

    result=output.stdout.decode(encoding='utf-8',errors='ignore')

    if result=='':
        result=f"Succes! {ip} will restart in {time} seconds"

    if len(result)>300:
        result="Error! Could be caused by invalid input!"

    out.append(result)