
rule Trojan_BAT_LimeRAT_NEC_MTB{
	meta:
		description = "Trojan:BAT/LimeRAT.NEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 03 02 4b 03 04 5f 03 66 05 5f 60 58 0e 07 0e 04 e0 95 58 7e bb 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 cd 02 00 06 58 54 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}