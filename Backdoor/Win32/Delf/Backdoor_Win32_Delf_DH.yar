
rule Backdoor_Win32_Delf_DH{
	meta:
		description = "Backdoor:Win32/Delf.DH,SIGNATURE_TYPE_PEHSTR_EXT,ffffff90 00 ffffff90 00 09 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_00_1 = {6d 73 75 70 64 61 74 65 2e 65 78 65 } //10 msupdate.exe
		$a_00_2 = {65 72 61 73 65 20 22 25 73 22 } //10 erase "%s"
		$a_00_3 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f } //10 if exist "%s" Goto
		$a_02_4 = {5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c [0-08] 2e 65 78 65 } //10
		$a_00_5 = {57 53 41 53 74 61 72 74 75 70 } //1 WSAStartup
		$a_00_6 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_00_7 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_00_8 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 73 65 72 76 69 63 65 73 } //1 Software\Microsoft\Windows\CurrentVersion\Runservices
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_02_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=144
 
}