
rule Trojan_BAT_LummaC_AAH_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 2f 17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 } //1
		$a_03_1 = {11 9d 11 9c 16 6f ?? 00 00 0a 61 d2 13 9d 11 73 11 72 31 10 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*4) >=5
 
}