
rule Trojan_BAT_LummaC_EAHG_MTB{
	meta:
		description = "Trojan:BAT/LummaC.EAHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0d 28 64 00 00 06 13 17 11 0d 6f 9a 00 00 06 13 18 11 04 11 17 11 18 6f 4d 00 00 0a 11 16 17 58 13 16 11 16 11 0c 3f d4 ff ff ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}