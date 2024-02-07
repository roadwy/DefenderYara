
rule Trojan_BAT_Darkcomet_ABIU_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.ABIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 04 11 06 08 11 06 91 09 11 06 09 8e 69 5d 91 11 05 58 20 00 02 00 00 5f 61 d2 9c 11 06 17 58 } //01 00 
		$a_01_1 = {53 68 65 65 69 74 } //01 00  Sheeit
		$a_01_2 = {69 00 6d 00 67 00 } //00 00  img
	condition:
		any of ($a_*)
 
}