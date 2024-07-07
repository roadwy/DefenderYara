
rule TrojanDownloader_Win32_Wintrim_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Wintrim.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {8b c1 33 d2 f7 f6 8a 04 3a 30 04 19 41 3b 4d 0c 72 ee } //1
		$a_00_1 = {57 41 4f 4c 2e 45 58 45 } //1 WAOL.EXE
		$a_00_2 = {45 47 44 48 54 4d 4c } //1 EGDHTML
		$a_00_3 = {4f 70 65 6e 69 6e 67 20 74 68 65 20 70 6f 72 74 2e 2e 2e } //1 Opening the port...
		$a_00_4 = {52 65 67 69 73 74 65 72 69 6e 67 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 6f 6e 20 74 68 65 20 6e 65 74 77 6f 72 6b 2e 2e 2e } //1 Registering your computer on the network...
		$a_00_5 = {41 6c 6c 20 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 20 68 61 76 65 20 62 65 65 6e 20 63 6c 6f 73 65 64 2e } //1 All Internet Explorer have been closed.
		$a_00_6 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 45 47 44 41 43 43 45 53 53 2e 64 6c 6c } //1 rundll32.exe EGDACCESS.dll
		$a_01_7 = {58 4f 52 46 69 6c 65 32 46 69 6c 65 20 3a 20 } //1 XORFile2File : 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}