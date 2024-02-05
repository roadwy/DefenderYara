
rule Trojan_Win32_GuLoader_RPK_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f ae f0 81 f5 90 02 10 55 90 02 10 59 90 02 10 89 0c 37 90 02 10 4e 90 02 10 4e 90 02 10 4e 90 02 10 4e 7d 90 02 10 89 f9 90 02 10 51 90 02 10 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_GuLoader_RPK_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 2c 17 f7 c3 90 02 20 90 13 90 02 20 90 13 90 02 10 81 f5 90 02 20 90 13 90 02 20 90 13 90 02 10 01 2c 10 90 02 20 90 13 90 02 20 90 13 90 02 20 90 13 90 02 10 83 da 04 90 02 20 90 13 0f 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}