
rule Trojan_BAT_AgentTesla_BDT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_02_0 = {01 25 16 02 28 90 01 03 06 a2 28 90 01 03 06 74 90 01 03 01 13 90 01 01 16 7e 90 01 03 04 90 01 05 26 1b 90 01 05 09 6f 90 01 03 0a 08 20 00 01 00 00 14 09 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_3 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 2e 64 6c 6c } //01 00  ClassLibrary1.dll
		$a_81_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_5 = {53 74 75 62 53 74 61 74 75 73 53 74 72 61 74 65 67 79 } //00 00  StubStatusStrategy
	condition:
		any of ($a_*)
 
}