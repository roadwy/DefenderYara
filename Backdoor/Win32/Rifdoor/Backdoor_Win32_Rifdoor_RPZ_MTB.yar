
rule Backdoor_Win32_Rifdoor_RPZ_MTB{
	meta:
		description = "Backdoor:Win32/Rifdoor.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 55 70 64 61 74 65 5c 57 77 61 6e 73 76 63 2e 65 78 65 22 20 2f 72 75 6e } //1 "C:\ProgramData\Update\Wwansvc.exe" /run
		$a_01_1 = {2f 63 20 64 65 6c 20 2f 71 20 22 25 73 22 20 3e 3e 20 4e 55 4c } //1 /c del /q "%s" >> NUL
		$a_01_2 = {72 69 66 6c 65 2e 70 64 62 } //1 rifle.pdb
		$a_01_3 = {57 69 6e 64 6f 77 20 55 70 64 61 74 65 } //1 Window Update
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_01_5 = {44 65 6c 65 74 65 55 72 6c 43 61 63 68 65 45 6e 74 72 79 } //1 DeleteUrlCacheEntry
		$a_01_6 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
		$a_01_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}