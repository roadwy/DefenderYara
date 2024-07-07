
rule Trojan_BAT_LummaC_MDAA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.MDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 07 02 07 91 66 d2 9c 02 07 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 1f 72 58 d2 81 90 01 01 00 00 01 02 07 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 1f 34 59 d2 81 90 01 01 00 00 01 00 07 17 58 0b 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}