
rule Trojan_BAT_AgentTesla_Y_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {80 05 00 00 04 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 80 ?? ?? ?? 04 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}