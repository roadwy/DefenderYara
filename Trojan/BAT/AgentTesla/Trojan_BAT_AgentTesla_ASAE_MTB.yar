
rule Trojan_BAT_AgentTesla_ASAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {04 16 06 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 72 } //3
		$a_03_1 = {20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 07 a2 6f } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}