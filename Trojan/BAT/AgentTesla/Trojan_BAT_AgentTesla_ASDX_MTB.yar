
rule Trojan_BAT_AgentTesla_ASDX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 1c 11 21 20 00 01 00 00 5d d2 9c 00 11 1b 17 59 13 1b 11 1b 16 fe 04 16 fe 01 13 22 11 22 2d } //01 00 
		$a_01_1 = {47 00 38 00 46 00 5a 00 48 00 47 00 58 00 30 00 41 00 39 00 50 00 4a 00 33 00 35 00 35 00 38 00 34 00 37 00 47 00 49 00 46 00 38 00 } //00 00  G8FZHGX0A9PJ355847GIF8
	condition:
		any of ($a_*)
 
}