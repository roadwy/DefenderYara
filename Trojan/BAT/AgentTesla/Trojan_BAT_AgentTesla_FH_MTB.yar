
rule Trojan_BAT_AgentTesla_FH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 0d 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 34 34 31 32 37 30 33 38 2d 31 66 33 62 2d 34 62 37 61 2d 39 33 62 34 2d 35 32 31 34 61 33 62 33 39 31 32 34 } //14 00  $44127038-1f3b-4b7a-93b4-5214a3b39124
		$a_81_1 = {24 33 38 36 63 62 66 39 36 2d 37 31 63 36 2d 34 66 35 34 2d 61 35 34 34 2d 38 61 66 37 31 31 30 66 38 31 39 38 } //01 00  $386cbf96-71c6-4f54-a544-8af7110f8198
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_3 = {4a 61 6d 69 6c 73 5f 47 6f 6f 64 5f 4f 6c 64 5f 46 75 6e 5f 46 61 6d 69 6c 79 5f 43 65 6e 74 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Jamils_Good_Old_Fun_Family_Center.My.Resources
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_5 = {43 61 72 5f 53 65 72 76 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Car_Server.My.Resources
		$a_81_6 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerStepThroughAttribute
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_81_9 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_81_10 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_81_11 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_12 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}