
rule Trojan_BAT_AgentTesla_W_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {01 0a 19 8d ?? ?? ?? 01 25 16 7e ?? ?? ?? 04 a2 25 17 28 ?? ?? ?? 06 a2 25 18 72 ?? ?? ?? ?? a2 0a 06 73 ?? ?? ?? 06 0b 2b } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}