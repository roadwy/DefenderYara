
rule Trojan_BAT_LummaC_ALC_MTB{
	meta:
		description = "Trojan:BAT/LummaC.ALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 06 02 11 05 8f 1e 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58 13 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LummaC_ALC_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.ALC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {5d 13 2f 11 30 11 2d 11 2f 91 58 28 ?? 00 00 0a 11 31 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 30 73 28 00 00 0a 13 34 11 34 11 2d 11 30 91 6f ?? 00 00 0a 11 2d 11 30 11 2d 11 2f 91 9c 11 } //2
		$a_03_1 = {0d 13 04 16 13 05 2b 20 11 04 11 05 91 13 06 09 72 ?? 00 00 70 11 06 8c ?? 00 00 01 6f ?? 00 00 0a 26 11 05 17 58 13 05 11 05 11 04 8e 69 32 d8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}