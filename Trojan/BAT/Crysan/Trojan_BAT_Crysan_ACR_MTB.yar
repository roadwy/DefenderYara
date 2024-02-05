
rule Trojan_BAT_Crysan_ACR_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a de 03 26 de 00 72 90 01 01 00 00 70 0a 72 90 01 01 00 00 70 06 28 90 01 01 00 00 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}