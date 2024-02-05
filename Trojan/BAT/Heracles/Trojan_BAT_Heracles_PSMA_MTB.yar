
rule Trojan_BAT_Heracles_PSMA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PSMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 0e 00 00 06 0a 28 20 00 00 0a 06 6f 21 00 00 0a 28 0f 00 00 06 75 06 00 00 1b 28 10 00 00 06 2a } //00 00 
	condition:
		any of ($a_*)
 
}