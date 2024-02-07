
rule Trojan_BAT_AgentTesla_NOB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 39 37 34 38 64 64 65 64 2d 65 37 36 61 2d 34 64 63 36 2d 39 30 36 31 2d 63 35 36 39 33 35 63 32 34 66 62 36 } //01 00  $9748dded-e76a-4dc6-9061-c56935c24fb6
		$a_01_1 = {56 65 6e 64 69 6e 67 4d 61 63 68 69 6e 65 4d 6b 32 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //01 00  VendingMachineMk2.Properties.Resources.resource
		$a_01_2 = {49 44 65 66 65 72 72 65 64 } //01 00  IDeferred
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_4 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_01_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}