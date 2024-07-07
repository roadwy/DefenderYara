
rule Trojan_Win32_Adept_A{
	meta:
		description = "Trojan:Win32/Adept.A,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 0a 00 00 "
		
	strings :
		$a_00_0 = {77 75 61 75 73 65 72 76 } //10 wuauserv
		$a_00_1 = {5c 73 79 73 74 65 6d 25 64 2e 65 78 65 } //10 \system%d.exe
		$a_02_2 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 90 02 08 2e 61 78 90 00 } //10
		$a_00_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 WriteProcessMemory
		$a_00_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //10 InternetReadFile
		$a_00_5 = {41 55 20 73 65 72 76 69 63 65 } //1 AU service
		$a_00_6 = {49 4e 4a 45 43 54 20 69 73 20 6e 65 65 64 65 64 } //1 INJECT is needed
		$a_00_7 = {41 75 74 6f 6d 61 74 69 63 20 75 70 64 61 74 65 73 20 73 65 72 76 69 63 65 } //1 Automatic updates service
		$a_00_8 = {45 78 70 6c 6f 72 65 72 2e 65 78 65 20 68 61 73 20 62 65 65 6e 20 66 6f 75 6e 64 } //1 Explorer.exe has been found
		$a_00_9 = {53 69 67 6e 61 74 75 72 65 20 6f 66 20 64 6f 77 6e 6c 6f 61 64 65 64 20 66 69 6c 65 20 69 73 20 43 4f 52 52 45 43 54 } //1 Signature of downloaded file is CORRECT
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_02_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=51
 
}