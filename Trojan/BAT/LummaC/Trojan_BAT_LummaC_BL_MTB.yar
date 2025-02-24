
rule Trojan_BAT_LummaC_BL_MTB{
	meta:
		description = "Trojan:BAT/LummaC.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 2d 17 58 7e ?? 00 00 04 28 ?? 00 00 06 11 2f 7e ?? 00 00 04 28 ?? 00 00 06 7e ?? 00 00 04 28 ?? 00 00 06 7e ?? 00 00 04 28 ?? 00 00 06 5d } //3
		$a_03_1 = {02 11 31 8f ?? 00 00 01 25 47 11 35 16 6f ?? 00 00 0a 61 d2 52 38 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}
rule Trojan_BAT_LummaC_BL_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 02 28 ?? 00 00 0a 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 06 de } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}