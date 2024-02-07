
rule Trojan_BAT_Formbook_EL_MTB{
	meta:
		description = "Trojan:BAT/Formbook.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 0a 00 00 0a 00 "
		
	strings :
		$a_81_0 = {24 30 63 63 65 63 65 66 66 2d 66 32 39 62 2d 34 30 62 33 2d 62 35 37 62 2d 63 31 33 33 63 36 33 66 34 62 66 36 } //0a 00  $0cceceff-f29b-40b3-b57b-c133c63f4bf6
		$a_81_1 = {50 75 62 6c 69 73 68 65 72 4d 65 6d 62 65 72 73 68 69 70 43 6f 6e 64 69 74 69 6f 6e 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //05 00  PublisherMembershipCondition.My.Resources
		$a_81_2 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //05 00  DebuggerBrowsableState
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //05 00  DebuggerNonUserCodeAttribute
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //05 00  DebuggableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_7 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_8 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //01 00  Create__Instance__
		$a_81_9 = {47 65 74 49 6e 73 74 61 6e 63 65 } //00 00  GetInstance
	condition:
		any of ($a_*)
 
}