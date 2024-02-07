
rule Trojan_BAT_AgentTesla_BBO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 08 18 2c 90 02 01 17 58 0c 08 07 8e 69 32 90 02 01 06 6f 90 01 03 0a 28 90 01 03 0a 2a 73 90 01 03 0a 90 01 05 0a 90 01 05 6f 90 01 03 0a 2b 90 00 } //01 00 
		$a_81_1 = {54 6f 49 6e 74 33 32 } //01 00  ToInt32
		$a_81_2 = {53 74 61 72 74 54 65 73 74 73 } //01 00  StartTests
		$a_81_3 = {52 65 66 52 65 67 4d 6f 64 65 6c } //01 00  RefRegModel
		$a_81_4 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //00 00  ClassLibrary
	condition:
		any of ($a_*)
 
}