
rule Trojan_BAT_AgentTesla_BBG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {11 04 02 28 90 01 03 06 6f 90 01 03 0a 6f 90 01 03 0a 11 0c 11 04 6f 90 01 03 0a 28 90 01 03 06 13 05 11 05 17 8d 90 01 03 01 25 16 02 28 90 01 03 06 a2 6f 90 01 03 0a 74 90 01 03 01 13 0a 38 90 00 } //01 00 
		$a_81_1 = {43 61 6c 6c 54 65 73 74 73 } //01 00  CallTests
		$a_81_2 = {53 74 61 72 74 54 65 73 74 73 } //01 00  StartTests
		$a_81_3 = {52 65 66 52 65 67 4d 6f 64 65 6c } //01 00  RefRegModel
		$a_81_4 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //00 00  ClassLibrary
	condition:
		any of ($a_*)
 
}