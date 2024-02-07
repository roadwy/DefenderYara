
rule Trojan_BAT_AgentTesla_BML_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {0a 0c 1e 8d 90 01 03 01 0d 08 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 6f 90 01 03 0a 13 04 11 04 16 09 16 1e 28 90 01 03 0a 00 07 09 6f 90 01 03 0a 00 07 18 6f 90 01 03 0a 00 07 6f 90 01 03 0a 03 16 03 8e 69 6f 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}