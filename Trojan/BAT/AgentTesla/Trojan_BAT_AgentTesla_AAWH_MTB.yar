
rule Trojan_BAT_AgentTesla_AAWH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AAWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 0a 12 00 28 ?? 00 00 06 06 72 43 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 28 ?? 00 00 06 28 ?? 00 00 06 2a } //4
		$a_01_1 = {7a 00 7a 00 7a 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 58 00 } //1 zzzXXXXXXXXX
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}