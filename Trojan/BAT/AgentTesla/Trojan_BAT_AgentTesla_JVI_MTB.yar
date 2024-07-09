
rule Trojan_BAT_AgentTesla_JVI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 13 04 06 11 04 28 ?? ?? ?? 0a 07 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 00 09 17 d6 0d 09 08 6f ?? ?? ?? 0a fe 04 13 05 11 05 2d c8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}