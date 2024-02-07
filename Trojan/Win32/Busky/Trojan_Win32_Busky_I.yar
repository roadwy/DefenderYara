
rule Trojan_Win32_Busky_I{
	meta:
		description = "Trojan:Win32/Busky.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 94 14 00 00 90 03 02 00 90 13 90 02 11 e8 90 01 04 68 90 01 03 00 68 90 01 03 00 c3 90 00 } //01 00 
		$a_01_1 = {00 87 04 75 1f ef d0 11 98 88 00 60 97 de ac f9 } //01 00 
		$a_01_2 = {61 56 31 39 44 00 } //00 00  噡㤱D
	condition:
		any of ($a_*)
 
}