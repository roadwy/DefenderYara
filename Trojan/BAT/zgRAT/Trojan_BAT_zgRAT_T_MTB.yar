
rule Trojan_BAT_zgRAT_T_MTB{
	meta:
		description = "Trojan:BAT/zgRAT.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 04 20 00 01 00 00 0e 04 50 74 ?? 00 00 01 0e 04 50 28 ?? 00 00 0a 28 ?? ?? 00 06 05 6f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_BAT_zgRAT_T_MTB_2{
	meta:
		description = "Trojan:BAT/zgRAT.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 18 5a 58 0a 38 ?? 00 00 00 06 07 19 5a 58 0a 38 ?? 00 00 00 06 07 1a 5a 58 0a 07 17 58 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}