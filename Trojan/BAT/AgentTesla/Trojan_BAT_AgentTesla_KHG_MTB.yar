
rule Trojan_BAT_AgentTesla_KHG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.KHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {16 9a 0b 02 07 28 ?? ?? ?? ?? ?? 16 28 ?? ?? ?? ?? 00 2a 90 09 16 00 28 [0-0f] 0a 06 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}