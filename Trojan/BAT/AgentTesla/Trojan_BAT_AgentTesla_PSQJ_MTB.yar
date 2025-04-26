
rule Trojan_BAT_AgentTesla_PSQJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSQJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b7 6f 47 00 00 0a 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 13 04 73 ?? ?? ?? 0a 13 05 11 05 11 04 17 73 ?? ?? ?? 0a 25 03 16 03 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 05 6f 50 00 00 0a 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}