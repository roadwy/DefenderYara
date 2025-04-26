
rule Backdoor_Win32_Xema_gen_A{
	meta:
		description = "Backdoor:Win32/Xema.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,ffffff91 01 ffffff91 01 09 00 00 "
		
	strings :
		$a_02_0 = {ba 01 00 00 80 8b ?? e8 ?? ?? ?? ff b1 01 ba ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ff b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b } //100
		$a_02_1 = {ba 02 00 00 80 8b ?? e8 ?? ?? ?? ff b1 01 ba ?? ?? ?? ?? 8b ?? e8 ?? ?? ?? ff b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8b } //100
		$a_00_2 = {43 6f 70 79 46 69 6c 65 41 } //1 CopyFileA
		$a_01_3 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 73 79 73 73 6d 73 73 2e 65 78 65 } //100 C:\Program Files\Internet Explorer\syssmss.exe
		$a_01_4 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6f 6d 5c 63 6f 6e 5c 77 69 6e 73 65 72 76 5c 77 69 6e 73 65 72 76 2e 65 78 65 } //100 c:\windows\system32\com\con\winserv\winserv.exe
		$a_01_5 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 79 73 74 65 6d 33 32 5c 73 79 73 74 65 6d 33 32 2e 65 78 65 } //100 C:\WINDOWS\System32\system32.exe
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //100 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_7 = {57 69 6e 73 53 79 73 74 65 6d } //100 WinsSystem
		$a_01_8 = {77 69 6e 73 65 72 76 75 } //100 winservu
	condition:
		((#a_02_0  & 1)*100+(#a_02_1  & 1)*100+(#a_00_2  & 1)*1+(#a_01_3  & 1)*100+(#a_01_4  & 1)*100+(#a_01_5  & 1)*100+(#a_00_6  & 1)*100+(#a_01_7  & 1)*100+(#a_01_8  & 1)*100) >=401
 
}