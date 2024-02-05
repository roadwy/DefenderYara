
rule Constructor_Win32_VB_K{
	meta:
		description = "Constructor:Win32/VB.K,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6c 73 46 69 6c 65 42 69 6e 64 65 72 } //02 00 
		$a_01_1 = {74 78 74 45 58 45 31 } //04 00 
		$a_00_2 = {5c 00 45 00 58 00 45 00 20 00 4a 00 6f 00 69 00 6e 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}