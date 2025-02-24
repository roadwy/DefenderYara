
rule Trojan_BAT_LummaC_ATKA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ATKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 36 11 34 16 6f ?? 00 00 0a 61 d2 13 36 38 } //3
		$a_03_1 = {11 2b 11 2d 91 11 2b 11 2e 91 58 7e ?? 01 00 04 28 ?? 03 00 06 11 2f 7e ?? 01 00 04 28 ?? 04 00 06 7e ?? 01 00 04 28 ?? 04 00 06 7e ?? 01 00 04 28 ?? 04 00 06 5d 13 33 38 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}