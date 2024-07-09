
rule Trojan_BAT_AgentTesla_SPDI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 28 14 00 00 0a 06 6f ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a 0d 09 28 ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 74 13 00 00 01 13 04 11 04 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}