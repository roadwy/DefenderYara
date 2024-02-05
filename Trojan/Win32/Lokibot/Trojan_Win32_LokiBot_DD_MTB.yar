
rule Trojan_Win32_LokiBot_DD_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c7 8b de 8b d3 e8 90 01 02 ff ff 90 90 90 05 10 01 90 46 81 fe 90 01 02 00 00 75 90 00 } //01 00 
		$a_02_1 = {8b c8 03 ca 8b c2 b2 90 01 01 32 90 90 90 01 03 00 88 11 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_LokiBot_DD_MTB_2{
	meta:
		description = "Trojan:Win32/LokiBot.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 03 01 00 00 00 90 05 10 01 90 8b d0 03 13 90 05 10 01 90 c6 02 90 01 01 90 05 10 01 90 ff 03 81 3b 90 01 04 75 90 00 } //01 00 
		$a_03_1 = {8b 03 8a 80 90 01 04 a2 90 01 04 90 05 10 01 90 b0 6b 90 05 10 01 90 30 05 90 01 04 90 05 10 01 90 a0 90 01 04 e8 90 01 04 90 05 10 01 90 8b 07 40 89 07 90 05 10 01 90 ff 90 01 01 81 3b 90 01 04 75 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}