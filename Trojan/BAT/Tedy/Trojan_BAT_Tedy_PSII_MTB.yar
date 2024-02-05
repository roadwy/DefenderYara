
rule Trojan_BAT_Tedy_PSII_MTB{
	meta:
		description = "Trojan:BAT/Tedy.PSII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 28 19 00 00 0a 0a 06 02 7b 01 00 00 04 02 28 01 00 00 06 0b 28 1a 00 00 0a 07 6f 1b 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}