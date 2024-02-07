
rule Trojan_BAT_AgentTesla_DI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 0a 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 39 63 34 65 61 62 39 30 2d 34 66 33 39 2d 34 31 31 64 2d 38 35 64 61 2d 38 62 30 30 65 31 32 39 31 62 36 65 } //14 00  $9c4eab90-4f39-411d-85da-8b00e1291b6e
		$a_81_1 = {24 37 36 30 34 31 62 34 38 2d 36 64 38 61 2d 34 65 33 37 2d 39 33 64 34 2d 35 64 61 63 37 36 63 36 35 63 62 36 } //01 00  $76041b48-6d8a-4e37-93d4-5dac76c65cb6
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_3 = {4d 65 6e 74 51 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  MentQ.Properties.Resources
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_5 = {4c 6f 61 64 65 72 43 6f 64 65 53 65 6c 65 63 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  LoaderCodeSelector.Properties.Resources.resources
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_7 = {44 61 72 6b 55 49 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  DarkUI.Properties.Resources
		$a_81_8 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_81_9 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //00 00  DebuggingModes
	condition:
		any of ($a_*)
 
}