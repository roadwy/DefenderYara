
rule Trojan_BAT_LummaC_AUMA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AUMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 69 11 68 16 6f ?? 00 00 0a 61 d2 13 69 02 11 69 8c ?? 00 00 01 11 65 6f ?? 00 00 0a 11 65 17 58 13 65 } //3
		$a_03_1 = {11 2f 17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 11 31 5d 13 30 73 ?? 00 00 0a 13 66 11 66 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}