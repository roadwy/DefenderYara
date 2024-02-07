
rule Trojan_Win32_Busky_J{
	meta:
		description = "Trojan:Win32/Busky.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b8 94 14 00 00 } //01 00 
		$a_01_1 = {00 87 04 75 1f ef d0 11 98 88 00 60 97 de ac f9 } //01 00 
		$a_00_2 = {81 7d fc 80 00 00 00 0f 8d } //01 00 
		$a_01_3 = {61 56 31 39 44 00 } //00 00  噡㤱D
	condition:
		any of ($a_*)
 
}