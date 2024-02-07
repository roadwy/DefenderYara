
rule Trojan_BAT_AgentTesla_LHD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 58 31 00 } //01 00 
		$a_01_1 = {00 58 58 58 58 58 58 58 58 58 31 32 33 00 } //01 00  堀塘塘塘塘㈱3
		$a_01_2 = {46 48 4a 34 33 32 34 32 34 32 } //01 00  FHJ4324242
		$a_01_3 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00  GetObjectValue
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_6 = {43 68 61 72 54 6f 56 61 6c 75 65 } //01 00  CharToValue
		$a_01_7 = {4e 53 65 72 76 65 72 34 } //00 00  NServer4
	condition:
		any of ($a_*)
 
}