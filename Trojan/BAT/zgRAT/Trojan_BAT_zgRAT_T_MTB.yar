
rule Trojan_BAT_ZgRAT_T_MTB{
	meta:
		description = "Trojan:BAT/ZgRAT.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 18 5a 58 0a 38 ?? 00 00 00 06 07 19 5a 58 0a 38 ?? 00 00 00 06 07 1a 5a 58 0a 07 17 58 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}