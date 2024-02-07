
rule Trojan_BAT_AgentTesla_BOP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_02_0 = {26 20 00 00 00 00 38 90 01 04 11 00 6f 90 01 03 0a 72 90 01 03 70 20 00 01 00 00 14 11 00 17 8d 90 01 03 01 25 16 02 7e 90 01 03 04 28 90 01 03 06 a2 6f 90 01 03 0a 74 90 01 03 01 28 90 01 03 06 13 01 38 90 01 04 28 90 01 03 0a 13 00 38 90 00 } //01 00 
		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_2 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_3 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_5 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //00 00  ClassLibrary
	condition:
		any of ($a_*)
 
}