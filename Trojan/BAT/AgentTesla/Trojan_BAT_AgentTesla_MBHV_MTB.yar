
rule Trojan_BAT_AgentTesla_MBHV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 06 11 05 11 0f 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 0f 17 d6 13 0f 11 0f 11 0e 31 df } //1
		$a_01_1 = {44 00 65 00 6c 00 65 00 74 00 65 00 4d 00 43 00 } //1 DeleteMC
		$a_01_2 = {4c 00 6f 00 61 00 64 00 } //1 Load
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}