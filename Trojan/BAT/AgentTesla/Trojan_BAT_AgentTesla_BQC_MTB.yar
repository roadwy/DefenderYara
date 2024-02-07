
rule Trojan_BAT_AgentTesla_BQC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {14 0b 14 0c 16 0d 16 13 04 16 13 05 02 73 90 01 03 0a 16 73 90 01 03 0a 13 06 17 13 07 11 06 0c 00 2b 00 00 08 13 08 20 00 10 00 00 8d 90 01 03 01 13 09 73 90 01 03 0a 13 0a 00 00 08 11 09 16 20 00 10 00 00 6f 90 01 03 0a 13 0c 17 13 0d 11 0c 0d 00 2b 00 2b 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {54 61 73 6b 43 61 6e 63 65 6c 65 64 45 78 63 65 70 74 69 6f 6e } //01 00  TaskCanceledException
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}