
rule TrojanClicker_Win32_Agent_EG{
	meta:
		description = "TrojanClicker:Win32/Agent.EG,SIGNATURE_TYPE_PEHSTR,07 00 07 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 22 20 2f 76 20 44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 20 2f 74 20 72 65 67 5f 64 77 6f 72 64 20 2f 64 20 30 30 30 30 30 30 30 30 20 2f 66 } //1 \Policies\System" /v DisableRegistryTools /t reg_dword /d 00000000 /f
		$a_01_1 = {5c 41 64 76 61 6e 63 65 64 22 20 2f 76 20 53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e 20 2f 74 20 72 65 67 5f 64 77 6f 72 64 20 2f 64 20 30 30 30 30 30 30 30 30 20 2f 66 } //1 \Advanced" /v ShowSuperHidden /t reg_dword /d 00000000 /f
		$a_01_2 = {65 63 68 6f 20 5b 48 4b 45 59 5f 43 4c 41 53 53 45 53 5f 52 4f 4f 54 5c 6c 6e 6b 66 69 6c 65 5d 3e 3e 25 73 79 73 74 65 6d 72 6f 6f 74 25 } //1 echo [HKEY_CLASSES_ROOT\lnkfile]>>%systemroot%
		$a_01_3 = {45 78 70 6c 6f 72 65 72 5c 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 20 5c 22 68 74 74 70 3a 2f 2f 77 77 77 2e 35 71 62 62 2e 63 6f 6d 22 } //2 Explorer\\IEXPLORE.EXE \"http://www.5qbb.com"
		$a_01_4 = {6d 73 69 65 78 65 63 20 2f 72 65 67 73 65 72 76 65 72 } //1 msiexec /regserver
		$a_01_5 = {5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 33 36 30 74 72 61 79 2e 65 78 65 22 20 2f 76 20 44 65 62 75 67 67 65 72 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 } //1 \Image File Execution Options\360tray.exe" /v Debugger /t reg_sz /d
		$a_01_6 = {5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 63 68 72 6f 6d 65 2e 65 78 65 22 20 2f 76 20 44 65 62 75 67 67 65 72 20 2f 74 20 72 65 67 5f 73 7a 20 2f 64 } //1 \Image File Execution Options\chrome.exe" /v Debugger /t reg_sz /d
		$a_01_7 = {73 74 61 72 74 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 65 78 65 22 20 68 74 74 70 3a 2f 2f 68 61 6f 31 32 33 } //1 start "%ProgramFiles%\Internet Explorer\IEXPLORE.exe" http://hao123
		$a_01_8 = {41 54 54 52 49 42 20 2d 48 20 2d 52 20 2d 53 20 2d 41 20 63 3a 5c 47 52 4c 44 52 } //1 ATTRIB -H -R -S -A c:\GRLDR
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=7
 
}