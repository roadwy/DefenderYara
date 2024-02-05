
rule Trojan_BAT_Heracles_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6f 1b 00 00 0a 6f 1c 00 00 0a 7e 05 00 00 04 25 2d 17 26 7e 04 00 00 04 fe 06 0f 00 00 06 73 1d 00 00 0a 25 80 05 00 00 04 28 01 00 00 2b 0a 06 14 28 1f 00 00 0a 2c 09 06 14 14 6f 20 00 00 0a 26 2a } //00 00 
	condition:
		any of ($a_*)
 
}