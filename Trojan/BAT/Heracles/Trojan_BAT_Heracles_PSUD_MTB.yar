
rule Trojan_BAT_Heracles_PSUD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 02 7b 06 00 00 04 04 6f 90 01 01 00 00 0a 16 05 6f 90 01 01 00 00 0a 00 02 7b 09 00 00 04 04 05 02 7b 06 00 00 04 05 28 90 01 01 00 00 06 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}