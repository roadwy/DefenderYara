
rule Trojan_BAT_AgentTesla_LHN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 07 08 6f 90 01 03 0a 0d 02 16 16 6f 90 01 03 0a 13 04 09 11 04 28 90 01 03 0a 13 05 11 05 2c 68 00 06 19 8d 90 01 03 01 25 16 12 03 28 90 01 03 0a 9c 25 17 12 03 fe 90 01 05 6f 90 01 04 72 90 01 04 28 90 00 } //01 00 
		$a_03_1 = {0a 19 9a 72 90 01 04 72 90 01 04 6f 90 01 04 72 90 01 04 72 90 01 04 6f 90 01 04 28 90 01 04 d2 9c 25 18 12 03 28 90 01 03 0a 9c 6f 90 01 03 0a 00 00 00 08 17 58 0c 08 02 6f 90 01 03 0a 13 07 12 07 28 90 01 03 0a 17 59 fe 02 16 fe 01 13 06 11 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}