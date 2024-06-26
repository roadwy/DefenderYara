
rule Trojan_BAT_AgentTesla_CED_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {20 df 8e fb 0e 0b 07 20 e7 8e fb 0e fe 01 0c 08 2c 09 20 1f 8f fb 0e 0b 00 2b 34 07 20 f1 8e fb 0e fe 01 0d 09 2c 09 20 18 8f fb 0e 0b 00 2b 1f 00 20 07 8f fb 0e 0b 17 13 04 02 28 90 01 03 2b 16 02 6f 90 01 03 0a 28 90 01 03 0a 0a 2b 00 06 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CED_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {0b 07 16 73 90 01 03 0a 0c 20 00 00 10 00 8d 90 01 03 01 0d 38 90 01 04 06 09 16 11 04 6f 90 01 03 0a 08 09 16 09 8e 69 6f 90 01 03 0a 25 13 04 16 3d 90 01 04 06 6f 90 00 } //01 00 
		$a_81_1 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_81_3 = {47 5a 69 70 53 74 72 65 61 6d } //00 00  GZipStream
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_CED_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.CED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_02_0 = {43 00 6c 00 61 00 73 00 73 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 90 02 25 44 00 61 00 74 00 61 00 90 00 } //01 00 
		$a_02_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 90 02 25 44 61 74 61 90 00 } //01 00 
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_3 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_81_4 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_5 = {70 6f 40 77 65 72 73 68 65 40 6c 6c } //01 00  po@wershe@ll
		$a_81_6 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_7 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_8 = {41 73 73 65 6d 62 6c 79 52 65 73 6f 6c 76 65 } //00 00  AssemblyResolve
	condition:
		any of ($a_*)
 
}