
rule Trojan_BAT_AgentTesla_S_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.S!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {13 07 19 8d ?? ?? ?? 01 80 ?? ?? ?? 04 7e ?? ?? ?? 04 16 7e ?? ?? ?? 04 a2 7e ?? ?? ?? 04 17 7e ?? ?? ?? 04 a2 7e ?? ?? ?? 04 18 72 ?? ?? ?? ?? a2 02 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_S_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.S!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 12 00 00 0a 72 57 00 00 70 28 0d 00 00 06 6f 13 00 00 0a 28 13 00 00 06 28 02 00 00 2b 28 03 00 00 2b 13 02 38 00 00 00 00 dd 21 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}