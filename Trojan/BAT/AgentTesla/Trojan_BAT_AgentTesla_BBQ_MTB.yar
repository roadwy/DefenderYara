
rule Trojan_BAT_AgentTesla_BBQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0a 04 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6a 61 b7 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 26 06 04 6f ?? ?? ?? 0a 17 da fe 01 13 06 11 06 2c 04 16 0a 2b 04 06 17 d6 0a 07 18 d6 0b 07 11 04 31 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}