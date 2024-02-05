
rule Trojan_BAT_Heracles_PSPT_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 28 24 00 00 0a 0a 28 90 01 03 0a 02 6f 90 01 03 0a 0b 25 07 6f 90 01 03 0a 6f 90 01 03 0a 06 16 06 8e 69 6f 31 00 00 0a 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}