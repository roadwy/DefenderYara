
rule Trojan_BAT_AgentTesla_LBE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 9a 13 04 11 04 28 90 01 03 0a 23 90 01 07 40 59 28 90 01 03 0a b7 13 05 07 11 05 28 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 0b 00 09 17 d6 0d 09 08 8e 69 fe 04 13 06 11 06 2d 90 00 } //01 00 
		$a_01_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}