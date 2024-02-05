
rule Trojan_BAT_AgentTesla_LUA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 2b 23 11 06 06 07 28 90 01 03 06 13 08 11 08 28 90 01 03 0a 13 09 11 04 06 11 09 d2 6f 90 01 03 0a 07 17 58 0b 07 17 fe 04 13 0a 11 0a 2d d3 90 00 } //01 00 
		$a_01_1 = {54 6f 57 69 6e 33 32 } //00 00 
	condition:
		any of ($a_*)
 
}