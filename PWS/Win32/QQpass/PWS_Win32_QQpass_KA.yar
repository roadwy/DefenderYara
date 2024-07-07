
rule PWS_Win32_QQpass_KA{
	meta:
		description = "PWS:Win32/QQpass.KA,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {50 4c 41 54 37 4d 49 43 52 4f 53 4f 46 54 52 55 2e 45 58 45 } //1 PLAT7MICROSOFTRU.EXE
		$a_01_2 = {54 61 73 6b 4b 69 6c 6c 65 72 2e 65 78 65 } //1 TaskKiller.exe
		$a_01_3 = {73 68 6f 76 74 68 2e 65 78 65 } //1 shovth.exe
		$a_01_4 = {77 69 6e 73 6e 2e 65 78 65 } //1 winsn.exe
		$a_01_5 = {77 69 6e 73 6f 73 2e 65 78 65 } //1 winsos.exe
		$a_01_6 = {48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_7 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_8 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //1 FindNextFileA
		$a_01_9 = {47 65 74 57 69 6e 64 6f 77 73 44 69 72 65 63 74 6f 72 79 41 } //1 GetWindowsDirectoryA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}