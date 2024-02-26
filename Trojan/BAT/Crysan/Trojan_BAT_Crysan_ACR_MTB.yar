
rule Trojan_BAT_Crysan_ACR_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a de 03 26 de 00 72 90 01 01 00 00 70 0a 72 90 01 01 00 00 70 06 28 90 01 01 00 00 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Crysan_ACR_MTB_2{
	meta:
		description = "Trojan:BAT/Crysan.ACR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 01 00 00 06 0a 06 16 28 02 00 00 06 26 28 04 00 00 06 6f 05 00 00 0a 2a } //01 00 
		$a_01_1 = {7d 04 00 00 04 12 00 7b 05 00 00 04 0b 12 01 12 00 28 02 00 00 2b 12 00 7c 05 00 00 04 28 28 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}