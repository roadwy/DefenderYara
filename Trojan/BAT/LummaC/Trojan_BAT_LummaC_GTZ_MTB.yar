
rule Trojan_BAT_LummaC_GTZ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 37 1d 11 0d 5f 91 13 1f 11 1f 19 62 11 1f 1b 63 60 d2 13 1f 11 05 11 0d 11 05 11 0d 91 11 1f 61 d2 9c 11 0d 17 58 13 0d 11 0d 11 07 32 d1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}