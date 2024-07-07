
rule TrojanSpy_Win32_Broler_H_dha{
	meta:
		description = "TrojanSpy:Win32/Broler.H!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 63 63 4e 54 2e 65 78 65 } //1 PccNT.exe
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 75 61 6d 6f 6b 2e 63 6f 6d 2f 2f 73 68 6f 70 2f 2f 69 6d 67 2f 2f 6d 61 72 6b 73 5f 65 73 63 72 6f 77 2f 2f 69 6e 64 65 78 2e 70 68 70 } //1 http://www.suamok.com//shop//img//marks_escrow//index.php
		$a_01_2 = {43 3a 5c 55 73 65 72 73 5c 58 46 5c 44 6f 63 75 6d 65 6e 74 73 5c 56 69 73 75 61 6c 20 53 74 75 64 69 6f 20 32 30 31 30 5c 50 72 6f 6a 65 63 74 73 5c 41 42 4b 44 4c 4c 5c 52 65 6c 65 61 73 65 5c 41 42 4b 44 4c 4c 2e 70 64 62 } //1 C:\Users\XF\Documents\Visual Studio 2010\Projects\ABKDLL\Release\ABKDLL.pdb
		$a_01_3 = {74 61 73 6b 6d 67 74 2e 65 78 65 } //1 taskmgt.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}