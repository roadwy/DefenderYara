
rule TrojanDropper_Win32_SpamThru_gen_D{
	meta:
		description = "TrojanDropper:Win32/SpamThru.gen!D,SIGNATURE_TYPE_PEHSTR,08 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {77 6f 64 68 7a 62 2e 64 6c 6c } //1 wodhzb.dll
		$a_01_1 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6f 64 68 7a 62 2e 64 6c 6c } //1 C:\WINDOWS\SYSTEM32\odhzb.dll
		$a_01_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6f 64 68 7a 62 2e 64 6c 6c 22 2c 72 75 6e } //1 rundll32.exe "C:\WINDOWS\SYSTEM32\odhzb.dll",run
		$a_01_3 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 22 2c 72 75 6e } //1 rundll32.exe "%s",run
		$a_01_4 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 25 73 } //1 %s\Microsoft\%s
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //1 Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
		$a_01_6 = {25 64 5f 25 64 2e 64 6c 6c } //1 %d_%d.dll
		$a_01_7 = {68 73 35 70 64 6c 6c 76 34 25 64 } //1 hs5pdllv4%d
		$a_01_8 = {22 43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 6f 64 68 7a 62 2e 64 6c 6c 22 2c 72 75 6e } //1 "C:\WINDOWS\SYSTEM32\odhzb.dll",run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=6
 
}