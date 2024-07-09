
rule Trojan_BAT_AgentTesla_ABXH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABXH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 17 da 13 06 16 13 07 2b 19 08 07 11 07 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 07 17 d6 13 07 11 07 11 06 31 e1 } //4
		$a_01_1 = {44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 00 } //1 DeleteMC
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}