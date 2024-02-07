
rule Trojan_BAT_AgentTesla_CRN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CRN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 06 09 18 5a 18 28 90 01 03 06 1f 10 28 90 01 03 06 d2 90 00 } //01 00 
		$a_01_1 = {53 75 62 73 74 72 69 6e 67 } //01 00  Substring
		$a_01_2 = {54 6f 55 49 6e 74 33 32 } //01 00  ToUInt32
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_4 = {47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 } //01 00  GetTypeFromHandle
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}