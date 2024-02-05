
rule Trojan_BAT_AgentTesla_EVT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EVT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f 90 01 03 0a 13 0b 12 0b 28 90 01 03 0a 28 90 01 03 0a 16 11 04 09 1a 28 90 01 03 0a 09 1a 58 0d 08 17 58 0c 08 06 fe 04 13 08 11 08 2d ce 90 00 } //01 00 
		$a_01_1 = {54 6f 41 72 67 62 } //01 00 
		$a_01_2 = {47 65 74 50 69 78 65 6c } //00 00 
	condition:
		any of ($a_*)
 
}