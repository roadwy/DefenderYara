
rule Trojan_BAT_Racoon_RDC_MTB{
	meta:
		description = "Trojan:BAT/Racoon.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0c 08 02 16 02 8e 69 6f 07 00 00 0a 08 6f 08 00 00 0a 07 6f 09 00 00 0a 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}