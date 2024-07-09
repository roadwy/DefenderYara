
rule Trojan_BAT_AgentTesla_LGB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LGB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 32 00 08 09 11 04 6f ?? ?? ?? 0a 13 05 08 09 11 04 6f ?? ?? ?? 0a 13 06 11 06 28 ?? ?? ?? 0a 13 07 17 13 08 00 07 06 11 07 d2 9c 00 00 11 04 17 58 13 04 11 04 17 fe 04 13 09 11 09 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}