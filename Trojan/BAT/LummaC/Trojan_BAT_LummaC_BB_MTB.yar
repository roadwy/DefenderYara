
rule Trojan_BAT_LummaC_BB_MTB{
	meta:
		description = "Trojan:BAT/LummaC.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 2e 11 2b 11 2d 91 58 11 2c 11 2d 91 58 20 00 01 00 00 5d 13 2e 11 2b 11 2e 91 13 2f 11 2b 11 2e 11 2b 11 2d 91 9c 11 2b 11 2d 11 2f 9c 11 2d 17 58 13 2d 11 2d 20 00 01 00 00 3f c0 ff ff ff } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}