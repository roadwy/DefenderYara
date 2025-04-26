
rule Trojan_BAT_LummaC_AWJA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AWJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 11 30 8f ?? 00 00 01 25 47 11 33 16 6f ?? 00 00 0a 61 d2 52 38 } //4
		$a_03_1 = {11 2d 17 58 28 ?? 00 00 0a 72 f8 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2d 38 } //2
		$a_03_2 = {11 2e 11 2b 11 2d 91 58 28 ?? 00 00 0a 72 f8 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2e } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=8
 
}