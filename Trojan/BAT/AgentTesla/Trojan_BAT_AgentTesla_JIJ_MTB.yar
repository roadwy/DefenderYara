
rule Trojan_BAT_AgentTesla_JIJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JIJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {20 00 01 00 00 38 90 01 03 00 00 38 90 01 03 00 20 90 01 03 00 38 90 01 03 00 00 38 90 01 03 00 7b 90 01 03 04 38 90 01 03 00 7b 90 01 03 04 20 90 01 03 00 38 90 01 03 00 0b 06 07 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 06 07 06 6f 90 01 03 0a 1e 5b 6f 90 01 03 0a 6f 90 01 03 0a 00 06 17 6f 90 01 03 0a 00 02 06 6f 90 00 } //01 00 
		$a_81_1 = {53 68 6f 62 68 61 } //01 00  Shobha
		$a_81_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_3 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_81_4 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_81_5 = {00 53 70 6f 74 69 66 79 00 78 6d 72 69 67 00 } //00 00 
	condition:
		any of ($a_*)
 
}