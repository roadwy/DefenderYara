
rule Trojan_BAT_AgentTesla_CFC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {08 09 08 28 90 01 03 06 5d 17 d6 28 90 01 03 06 da 13 04 90 09 07 00 06 09 28 90 01 03 06 90 00 } //01 00 
		$a_81_1 = {54 68 72 65 61 64 50 6f 6f 6c 2e 4c 69 67 68 74 } //01 00  ThreadPool.Light
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {47 65 74 43 68 61 72 } //00 00  GetChar
	condition:
		any of ($a_*)
 
}