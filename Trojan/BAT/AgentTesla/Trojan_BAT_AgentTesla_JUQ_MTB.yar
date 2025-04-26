
rule Trojan_BAT_AgentTesla_JUQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 6f ?? ?? ?? 0a 13 06 12 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 09 06 1a 28 ?? ?? ?? 0a 06 1a 58 0a 11 05 17 58 13 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}