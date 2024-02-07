
rule Trojan_BAT_Heracles_NHS_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {6f 0e 00 00 0a 07 6f 90 01 01 00 00 0a 17 73 90 01 01 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f 90 01 01 00 00 0a 90 00 } //01 00 
		$a_01_1 = {52 00 61 00 6e 00 63 00 68 00 72 00 6f 00 73 00 65 00 32 00 32 00 } //00 00  Ranchrose22
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Heracles_NHS_MTB_2{
	meta:
		description = "Trojan:BAT/Heracles.NHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {72 bf 09 00 70 0a 73 90 01 03 0a 25 6f 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 25 6f 90 01 03 0a 17 6f 90 01 03 0a 25 6f 90 01 03 0a 16 6f 90 01 03 0a 25 6f 90 01 03 0a 26 25 6f 90 01 03 0a 06 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {57 6f 74 75 63 53 6f 66 74 57 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //00 00  WotucSoftWare.Properties.Resources.resources
	condition:
		any of ($a_*)
 
}