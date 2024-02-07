
rule Trojan_BAT_AgentTesla_BEJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BEJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0b 09 20 90 01 04 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 13 04 06 11 04 6f 90 01 03 0a 06 18 6f 90 01 03 0a 02 6f 90 01 03 0a 16 02 6f 90 01 03 0a 28 90 01 03 0a 0c 28 90 01 03 0a 06 6f 90 01 03 0a 08 16 08 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 0b 07 90 00 } //0a 00 
		$a_02_1 = {70 0c 07 20 90 01 04 28 90 01 03 0a 03 6f 90 01 03 0a 6f 90 01 03 0a 0d 06 09 6f 90 01 03 0a 00 06 18 6f 90 01 03 0a 00 02 6f 90 01 03 0a 16 02 6f 90 01 03 0a 28 90 01 03 0a 13 04 28 90 01 03 0a 06 6f 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 6f 90 01 03 0a 0c 08 90 00 } //01 00 
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_3 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}