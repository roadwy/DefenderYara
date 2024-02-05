
rule Trojan_BAT_Scarsi_NEAA_MTB{
	meta:
		description = "Trojan:BAT/Scarsi.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {73 10 00 00 0a 25 28 11 00 00 0a 28 06 00 00 06 6f 12 00 00 0a 6f 13 00 00 0a 28 01 00 00 2b 6f 15 00 00 0a 2a } //01 00 
		$a_01_1 = {53 61 6d 73 75 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}