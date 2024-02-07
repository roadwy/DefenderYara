
rule Trojan_BAT_AgentTesla_JCN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0a 02 06 6f 90 01 03 0a d4 8d 90 01 03 01 7d 90 01 03 04 06 02 7b 90 01 03 04 16 02 7b 90 01 03 04 8e 69 6f 90 01 03 0a 26 02 90 00 } //01 00 
		$a_81_1 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //01 00  DebuggingModes
		$a_81_2 = {43 6c 61 73 73 4c 69 62 72 61 72 79 } //01 00  ClassLibrary
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_81_4 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_5 = {47 65 74 53 74 72 69 6e 67 } //01 00  GetString
		$a_81_6 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //00 00  GetExecutingAssembly
	condition:
		any of ($a_*)
 
}