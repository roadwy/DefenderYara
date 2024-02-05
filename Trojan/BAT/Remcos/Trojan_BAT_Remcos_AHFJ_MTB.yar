
rule Trojan_BAT_Remcos_AHFJ_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AHFJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 08 2b 1d 07 06 11 08 9a 1f 10 28 90 01 03 0a 8c 54 00 00 01 6f 90 01 03 0a 26 11 08 17 58 13 08 11 08 90 00 } //01 00 
		$a_01_1 = {4d 00 69 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}