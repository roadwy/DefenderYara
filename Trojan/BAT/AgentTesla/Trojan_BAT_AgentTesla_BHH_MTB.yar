
rule Trojan_BAT_AgentTesla_BHH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0a 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 31 65 66 64 64 32 65 31 2d 34 61 38 31 2d 34 31 66 30 2d 61 30 61 31 2d 66 37 37 61 64 35 31 63 65 32 36 66 } //01 00  $1efdd2e1-4a81-41f0-a0a1-f77ad51ce26f
		$a_81_1 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_81_2 = {47 5a 69 70 53 74 72 65 61 6d } //01 00  GZipStream
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_6 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_81_7 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_81_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_9 = {43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 } //00 00  CompressionMode
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BHH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BHH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 16 9a 11 01 17 8d 90 01 03 01 25 16 28 90 01 03 06 a2 6f 90 01 03 0a 28 90 01 03 0a 38 90 01 04 28 90 01 03 0a 02 28 90 01 03 06 6f 90 01 03 0a 25 72 90 01 03 70 6f 90 01 03 0a 13 00 11 00 6f 90 01 03 0a 28 90 01 03 06 13 01 38 90 00 } //0a 00 
		$a_02_1 = {0a 0a 08 16 73 90 01 03 0a 73 90 01 03 0a 0b 16 7e 90 01 03 04 2d 03 26 11 04 45 01 90 01 07 2b 09 06 6f 90 01 03 0a 0d 2b 14 00 07 06 6f 90 01 03 0a de ed 07 2c 06 07 6f 90 01 03 0a dc dd 90 00 } //02 00 
		$a_81_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 2e 50 6f 6c 69 63 65 73 2e 50 6f 6f 6c } //01 00  ClassLibrary1.Polices.Pool
		$a_81_3 = {44 65 73 74 72 6f 79 44 65 66 69 6e 69 74 69 6f 6e } //01 00  DestroyDefinition
		$a_81_4 = {43 6c 61 73 73 4c 69 62 72 61 72 79 31 } //00 00  ClassLibrary1
	condition:
		any of ($a_*)
 
}