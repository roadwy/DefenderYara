
rule Trojan_Win32_DinaBot_SA{
	meta:
		description = "Trojan:Win32/DinaBot.SA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //01 00  rundll32.exe
		$a_02_1 = {73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 90 02 05 23 00 90 00 } //01 00 
		$a_00_2 = {73 00 79 00 73 00 77 00 6f 00 77 00 36 00 34 00 5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //00 00  syswow64\explorer.exe
	condition:
		any of ($a_*)
 
}