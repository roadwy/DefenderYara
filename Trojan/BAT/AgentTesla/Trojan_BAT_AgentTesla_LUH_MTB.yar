
rule Trojan_BAT_AgentTesla_LUH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 05 2b 2e 00 09 11 04 11 05 28 ?? ?? ?? 06 13 09 11 09 28 ?? ?? ?? 0a 13 0a 08 11 04 11 0a d2 8c ?? ?? ?? 01 6f ?? ?? ?? 0a 00 00 11 05 17 58 13 05 11 05 17 fe 04 13 0b 11 0b 2d c7 07 17 58 0b 00 11 04 17 58 13 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}