
rule Trojan_BAT_Marsilia_AMA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 17 6f ?? 00 00 0a 06 02 16 9a 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 25 06 6f ?? 00 00 0a 06 02 17 9a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Marsilia_AMA_MTB_2{
	meta:
		description = "Trojan:BAT/Marsilia.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 2f 07 16 28 ?? 00 00 0a 73 28 00 00 0a 05 11 04 94 28 ?? 00 00 0a 0d 02 7b 13 00 00 04 09 07 07 8e 69 12 02 28 ?? 00 00 06 26 11 04 17 58 13 04 11 04 05 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}