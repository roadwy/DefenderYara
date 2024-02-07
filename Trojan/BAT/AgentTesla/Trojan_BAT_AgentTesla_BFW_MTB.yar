
rule Trojan_BAT_AgentTesla_BFW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0b 00 00 07 0a 38 90 02 05 72 90 01 03 70 03 11 05 18 6f 90 01 03 0a 28 90 01 03 0a 28 90 01 03 0a 04 09 6f 90 01 03 0a 28 90 01 03 0a 6a 61 b7 28 90 01 03 0a 28 90 01 03 0a 13 0a 17 13 13 11 0a 13 06 00 2b 00 00 08 11 06 6f 90 01 03 0a 26 09 04 6f 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {49 53 65 63 74 69 6f 6e 45 6e 74 72 79 } //00 00  ISectionEntry
	condition:
		any of ($a_*)
 
}