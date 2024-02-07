
rule Trojan_Win32_Startpage_WL{
	meta:
		description = "Trojan:Win32/Startpage.WL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 32 36 35 2e 6c 61 2f 3f } //01 00  www.265.la/?
		$a_01_1 = {4c 00 6f 00 63 00 6b 00 50 00 61 00 67 00 65 00 2e 00 45 00 58 00 45 00 } //01 00  LockPage.EXE
		$a_01_2 = {54 54 72 61 76 65 7e 31 2e 65 78 65 } //01 00  TTrave~1.exe
		$a_01_3 = {53 6f 67 6f 75 45 7e 31 2e 65 78 65 } //01 00  SogouE~1.exe
		$a_01_4 = {31 32 33 34 35 36 } //00 00  123456
	condition:
		any of ($a_*)
 
}