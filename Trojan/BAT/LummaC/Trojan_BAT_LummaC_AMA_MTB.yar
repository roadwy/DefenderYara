
rule Trojan_BAT_LummaC_AMA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6e 5b 26 11 ?? 6e 11 ?? 6a 5b 26 11 [0-32] 0a 26 03 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 ?? 91 61 d2 81 ?? 00 00 01 de 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_LummaC_AMA_MTB_2{
	meta:
		description = "Trojan:BAT/LummaC.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 [0-32] 03 11 ?? 28 ?? 00 00 0a 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 ?? 28 ?? 00 00 0a 91 61 d2 81 ?? 00 00 01 de } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}