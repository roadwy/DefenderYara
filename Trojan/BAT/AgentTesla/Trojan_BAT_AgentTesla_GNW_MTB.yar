
rule Trojan_BAT_AgentTesla_GNW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GNW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {06 13 05 28 90 01 03 0a 11 05 6f 90 01 03 0a 13 06 11 06 28 90 01 03 0a 13 07 11 04 72 1c 01 00 70 90 00 } //01 00 
		$a_01_1 = {04 3b 04 4f 04 20 00 37 04 30 04 20 00 41 04 3e 04 32 04 35 04 40 04 48 04 35 04 3d 04 38 04 35 04 20 00 3e 04 3f 04 35 04 40 04 30 04 46 04 38 04 39 04 } //00 00 
	condition:
		any of ($a_*)
 
}