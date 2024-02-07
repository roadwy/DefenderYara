
rule Trojan_BAT_ClipBanker_DC_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {4f 49 41 44 4e 41 49 53 33 71 } //01 00  OIADNAIS3q
		$a_81_1 = {53 79 73 74 65 6d 53 74 72 69 6e 67 } //01 00  SystemString
		$a_81_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_4 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_81_5 = {49 73 4c 6f 67 67 69 6e 67 } //01 00  IsLogging
		$a_81_6 = {67 65 74 5f 49 73 41 6c 69 76 65 } //01 00  get_IsAlive
		$a_81_7 = {43 6f 6e 76 65 72 74 } //01 00  Convert
		$a_81_8 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}