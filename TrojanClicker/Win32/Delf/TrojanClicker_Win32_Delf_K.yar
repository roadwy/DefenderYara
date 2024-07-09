
rule TrojanClicker_Win32_Delf_K{
	meta:
		description = "TrojanClicker:Win32/Delf.K,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 0a 00 00 "
		
	strings :
		$a_02_0 = {63 3a 5c 6d 69 63 72 6f 73 6f 66 74 5c 00 00 00 [0-05] 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65 } //10
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_00_2 = {32 30 30 35 2d 73 65 61 72 63 68 2e 63 6f 6d 2f 67 6f 2e 70 68 70 } //3 2005-search.com/go.php
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 Software\Microsoft\Windows\CurrentVersion\Run
		$a_00_4 = {48 6f 6e 62 65 66 6f 72 65 75 6e 6c 6f 61 64 } //1 Honbeforeunload
		$a_00_5 = {54 69 6d 65 72 3a 20 53 74 61 72 74 69 6e 67 20 74 6f 20 63 6c 69 63 6b 2e 2e 2e 2e } //1 Timer: Starting to click....
		$a_00_6 = {46 6f 6c 64 65 72 5c 73 68 65 6c 6c 5c 65 78 70 6c 6f 72 65 5c 64 64 65 65 78 65 63 } //1 Folder\shell\explore\ddeexec
		$a_00_7 = {00 00 57 69 6e 68 6f 73 74 00 } //1
		$a_00_8 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 62 00 61 00 72 00 } //1 explorerbar
		$a_00_9 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //1 CallNextHookEx
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*3+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=27
 
}