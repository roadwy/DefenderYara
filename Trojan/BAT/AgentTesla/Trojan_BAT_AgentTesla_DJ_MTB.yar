
rule Trojan_BAT_AgentTesla_DJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 08 00 00 14 00 "
		
	strings :
		$a_81_0 = {4c 4f 4c 4c 61 6e 67 75 61 67 65 53 65 6c 65 63 74 6f 72 2e 55 49 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //14 00  LOLLanguageSelector.UI.Properties.Resources
		$a_81_1 = {56 61 6c 75 65 46 69 78 75 70 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  ValueFixup.My.Resources
		$a_81_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_3 = {6d 65 68 72 7a 61 64 79 40 67 6d 61 69 6c 2e 63 6f 6d } //01 00  mehrzady@gmail.com
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_5 = {44 65 76 6f 6c 65 70 6f 72 73 40 67 6d 61 6c 2e 63 6f 6d } //01 00  Devolepors@gmal.com
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //00 00  CreateInstance
	condition:
		any of ($a_*)
 
}