
rule Trojan_BAT_Zusy_PSTS_MTB{
	meta:
		description = "Trojan:BAT/Zusy.PSTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 99 02 00 70 28 90 01 01 00 00 0a 06 72 a7 02 00 70 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 06 28 90 01 01 00 00 0a 26 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}