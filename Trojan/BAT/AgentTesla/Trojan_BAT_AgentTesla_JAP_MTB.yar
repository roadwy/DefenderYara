
rule Trojan_BAT_AgentTesla_JAP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {01 0d 2b 13 08 09 16 09 8e 69 6f 90 01 03 0a 25 13 04 16 30 0e 2b 02 2b eb 06 28 90 01 03 06 13 05 2b 0c 06 09 16 11 04 6f 90 01 03 0a 2b d5 90 00 } //0a 00 
		$a_02_1 = {01 13 03 38 90 01 03 00 38 90 01 03 00 38 90 01 03 00 11 02 11 03 16 11 03 8e 69 6f 90 01 03 0a 25 13 04 16 3d 90 01 03 00 38 90 01 03 00 11 00 11 03 16 11 04 28 90 01 03 06 38 90 01 03 ff 11 00 6f 90 01 03 0a 13 05 38 90 00 } //01 00 
		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_3 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_81_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_5 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}