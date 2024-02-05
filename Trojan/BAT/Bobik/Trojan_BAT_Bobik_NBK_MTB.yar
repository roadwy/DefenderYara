
rule Trojan_BAT_Bobik_NBK_MTB{
	meta:
		description = "Trojan:BAT/Bobik.NBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 e8 01 00 0a 58 28 90 01 02 00 0a 61 69 61 69 fe 90 01 02 00 61 5e 90 00 } //01 00 
		$a_01_1 = {4e 20 53 70 6f 6f 66 65 72 } //01 00 
		$a_01_2 = {4e 65 6f 78 20 53 70 6f 6f 66 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Bobik_NBK_MTB_2{
	meta:
		description = "Trojan:BAT/Bobik.NBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 0a 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 00 28 90 01 01 00 00 0a 14 fe 90 01 04 06 73 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 06 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 00 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 26 90 00 } //01 00 
		$a_01_1 = {77 77 63 64 2e 65 78 65 } //01 00 
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 57 00 69 00 6e 00 2e 00 70 00 6e 00 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}