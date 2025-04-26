
rule Trojan_BAT_AgentTesla_ASAV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 16 06 7b ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 20 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}