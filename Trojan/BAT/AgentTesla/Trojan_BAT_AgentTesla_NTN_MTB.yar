
rule Trojan_BAT_AgentTesla_NTN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 7e 43 01 00 04 6f 90 01 03 0a 00 07 7e 90 01 03 04 6f 90 01 03 0a 00 07 7e 90 01 03 04 7e 90 01 03 04 6f 90 01 03 0a 90 00 } //01 00 
		$a_01_1 = {7a 63 34 76 32 45 4f } //01 00  zc4v2EO
		$a_01_2 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 52 00 65 00 63 00 75 00 72 00 73 00 69 00 76 00 65 00 46 00 6f 00 72 00 6d 00 43 00 72 00 65 00 61 00 74 00 65 00 } //01 00  WinForms_RecursiveFormCreate
		$a_01_3 = {42 6f 6f 6b 43 6c 75 62 4d 61 6e 61 67 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //00 00  BookClubManager.My.Resources
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NTN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 38 44 35 36 32 44 46 32 2d 34 37 33 32 2d 34 38 38 34 2d 39 35 45 41 2d 44 38 41 33 31 45 35 41 34 32 44 39 } //01 00  $8D562DF2-4732-4884-95EA-D8A31E5A42D9
		$a_01_1 = {50 61 72 61 65 64 75 63 61 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Paraeducator.Properties.Resources.resources
		$a_01_2 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  ToBase64String
		$a_01_3 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_NTN_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.NTN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 09 00 00 0a 00 "
		
	strings :
		$a_01_0 = {38 66 39 65 62 38 63 30 2d 33 63 38 36 2d 34 64 66 64 2d 38 31 30 34 2d 65 34 37 39 37 33 39 65 34 31 62 38 } //0a 00  8f9eb8c0-3c86-4dfd-8104-e479739e41b8
		$a_01_1 = {43 6f 6e 63 6f 75 72 73 5f 53 75 70 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Concours_Sup.Resources.resources
		$a_01_2 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_5 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } //01 00  GetExecutingAssembly
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_7 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_8 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //00 00  FromBase64CharArray
	condition:
		any of ($a_*)
 
}