
rule Trojan_BAT_Heracles_FXAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.FXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 1b 11 13 6f 90 01 01 00 00 0a 11 1b 11 14 6f 90 01 01 00 00 0a 11 1b 11 1b 6f 90 01 01 00 00 0a 11 1b 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 11 12 16 11 12 8e 69 6f 90 01 01 00 00 0a 13 1c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}