
rule Trojan_BAT_AgentTesla_ENE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ENE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 06 11 04 17 58 8c ?? ?? ?? 01 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 1b fe 04 13 05 11 05 2d d1 } //1
		$a_03_1 = {06 00 02 02 28 ?? ?? ?? 06 75 ?? ?? ?? 1b 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 00 72 ?? ?? ?? 70 06 28 ?? ?? ?? 06 00 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 00 72 ?? ?? ?? 70 06 28 ?? ?? ?? 06 00 02 28 ?? ?? ?? 06 00 2a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}