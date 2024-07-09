
rule Trojan_BAT_Seraph_KAC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 00 11 02 02 11 02 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_Seraph_KAC_MTB_2{
	meta:
		description = "Trojan:BAT/Seraph.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 11 05 16 6f ?? 00 00 0a 13 06 12 06 28 ?? 00 00 0a 13 07 11 04 11 07 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 09 6f ?? 00 00 0a 32 d3 } //5
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 30 00 34 00 2e 00 31 00 39 00 34 00 2e 00 31 00 32 00 38 00 2e 00 31 00 37 00 30 00 } //5 http://104.194.128.170
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}