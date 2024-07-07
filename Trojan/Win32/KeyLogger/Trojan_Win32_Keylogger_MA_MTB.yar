
rule Trojan_Win32_Keylogger_MA_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 08 00 00 "
		
	strings :
		$a_01_0 = {30 8b 41 00 34 8b 41 00 3c 8b 41 00 44 8b 41 00 50 8b 41 00 58 8b 41 00 64 8b 41 00 30 8b 41 } //5
		$a_01_1 = {6b 65 79 6c 6f 67 67 65 72 5c 73 6f 75 72 63 65 5c 44 65 62 75 67 5c 6b 65 79 6c 6f 67 67 65 72 2e 70 64 62 } //2 keylogger\source\Debug\keylogger.pdb
		$a_01_2 = {5b 4e 50 44 45 4c 5d } //2 [NPDEL]
		$a_01_3 = {5b 43 52 53 45 4c 5d } //2 [CRSEL]
		$a_01_4 = {5b 50 52 4f 43 45 53 53 4b 45 59 5d } //2 [PROCESSKEY]
		$a_01_5 = {5b 42 52 4f 57 53 45 52 5f 46 41 56 4f 52 49 54 45 53 5d } //2 [BROWSER_FAVORITES]
		$a_01_6 = {5b 4b 41 4e 4a 49 5d } //2 [KANJI]
		$a_01_7 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 57 } //1 SetWindowsHookExW
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*1) >=18
 
}