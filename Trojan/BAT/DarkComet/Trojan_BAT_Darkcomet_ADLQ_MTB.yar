
rule Trojan_BAT_Darkcomet_ADLQ_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.ADLQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 08 15 d6 0c 08 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}