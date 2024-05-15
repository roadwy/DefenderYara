
rule Trojan_BAT_RedLineStealer_KAI_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 11 0d 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 07 11 11 91 61 d2 90 00 } //01 00 
		$a_01_1 = {11 12 11 13 11 13 09 58 9e 11 13 17 58 13 13 11 13 11 12 8e 69 } //00 00 
	condition:
		any of ($a_*)
 
}