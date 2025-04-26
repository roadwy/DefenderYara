
rule Trojan_BAT_LummaC_AFNA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AFNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 9a 11 99 16 6f ?? 00 00 0a 61 d2 13 9a 02 11 65 11 9a 9c 11 65 17 58 13 65 } //3
		$a_03_1 = {11 2f 17 58 11 31 5d 13 2f 11 30 11 2d 11 2f 91 58 11 31 5d 13 30 73 ?? 00 00 0a 13 66 11 66 11 2d 11 30 91 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}