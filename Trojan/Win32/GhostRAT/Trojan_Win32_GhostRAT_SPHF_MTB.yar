
rule Trojan_Win32_GhostRAT_SPHF_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.SPHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 08 00 00 "
		
	strings :
		$a_01_0 = {74 61 73 6b 6c 69 73 74 20 2f 46 49 20 22 49 4d 41 47 45 4e 41 4d 45 20 65 71 20 25 50 72 6f 63 65 73 73 4e 61 6d 65 25 22 20 7c 20 66 69 6e 64 73 74 72 20 2f 49 20 22 25 50 72 6f 63 65 73 73 4e 61 6d 65 25 22 20 3e 6e 75 6c } //5 tasklist /FI "IMAGENAME eq %ProcessName%" | findstr /I "%ProcessName%" >nul
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 20 22 53 65 74 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 55 6e 72 65 73 74 72 69 63 74 65 64 20 2d 53 63 6f 70 65 20 43 75 72 72 65 6e 74 55 73 65 72 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 46 69 6c 65 } //4 powershell -Command "Set-ExecutionPolicy Unrestricted -Scope CurrentUser"powershell -ExecutionPolicy Bypass -File
		$a_01_2 = {59 58 4a 30 54 32 35 45 5a 57 31 68 62 6d 51 2b 64 48 4a 31 5a 54 77 76 51 57 78 73 62 33 64 54 64 47 46 79 64 45 39 75 52 47 56 74 59 57 35 6b 50 67 6f 67 49 43 41 67 50 45 56 75 59 57 4a 73 5a 57 51 2b 64 48 4a 31 5a } //4 YXJ0T25EZW1hbmQ+dHJ1ZTwvQWxsb3dTdGFydE9uRGVtYW5kPgogICAgPEVuYWJsZWQ+dHJ1Z
		$a_80_3 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 49 69 56 69 53 } //C:\Windows\IiViS  2
		$a_01_4 = {62 61 63 6b 75 70 2e 65 78 65 } //1 backup.exe
		$a_01_5 = {63 6f 70 79 20 2f 59 20 22 25 42 61 63 6b 75 70 44 4c 4c 50 61 74 68 25 22 20 22 25 44 4c 4c 50 61 74 68 25 22 } //1 copy /Y "%BackupDLLPath%" "%DLLPath%"
		$a_01_6 = {73 74 61 72 74 20 22 22 20 22 25 50 72 6f 63 65 73 73 50 61 74 68 25 22 } //1 start "" "%ProcessPath%"
		$a_01_7 = {74 69 6d 65 6f 75 74 20 2f 74 20 33 30 20 2f 6e 6f 62 72 65 61 6b } //1 timeout /t 30 /nobreak
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_80_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=19
 
}