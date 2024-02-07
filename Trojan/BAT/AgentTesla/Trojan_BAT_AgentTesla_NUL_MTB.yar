
rule Trojan_BAT_AgentTesla_NUL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NUL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 33 39 33 34 64 33 61 39 2d 65 32 64 39 2d 34 35 30 64 2d 61 64 34 63 2d 63 32 35 66 36 34 37 62 62 37 37 30 } //01 00  $3934d3a9-e2d9-450d-ad4c-c25f647bb770
		$a_01_1 = {41 50 43 44 2e 50 65 6f 70 6c 65 4c 69 62 72 61 72 79 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  APCD.PeopleLibrary.Resources.resources
		$a_81_2 = {47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65 } //01 00  GetObjectValue
		$a_81_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_81_4 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_6 = {54 6f 53 74 72 69 6e 67 } //00 00  ToString
	condition:
		any of ($a_*)
 
}