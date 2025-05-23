
rule PWS_Win32_OnLineGames_ZDR{
	meta:
		description = "PWS:Win32/OnLineGames.ZDR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {7e 44 46 44 00 00 00 00 25 64 00 00 2e 62 61 74 00 00 00 00 40 65 63 68 6f 20 6f 66 66 0d 0a 00 3a 4c 6f 6f 70 0d 0a 00 64 65 6c 20 22 00 00 00 22 0d 0a 00 69 66 20 65 78 69 73 74 20 22 00 00 22 20 67 6f 74 6f 20 4c 6f 6f 70 0d 0a 00 00 00 64 65 6c 20 25 30 0d 0a 00 00 00 00 } //3
		$a_03_1 = {4d 61 69 6e 2e 64 6c 6c 00 45 6e [0-01] 48 6f 6f 6b [0-01] 57 69 6e 64 6f 77 00 00 00 00 00 00 00 } //2
		$a_01_2 = {00 3f 61 63 74 3d 00 00 00 26 64 31 30 3d 00 00 00 3a 2f 2f 00 2f 00 00 00 6d 69 62 61 6f 2e 61 73 70 00 00 00 } //2
		$a_01_3 = {3a 2f 2f 00 68 74 74 70 3a 2f 2f 00 2f 00 00 00 47 45 54 20 00 00 00 00 20 48 54 54 50 2f 31 2e 31 0d 0a 00 48 6f 73 74 3a 20 00 00 0d 0a 0d 0a } //1
		$a_00_4 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 65 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //1 Software\Microsoft\Windows\CurrentVersion\explorer\ShellExecuteHooks
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}