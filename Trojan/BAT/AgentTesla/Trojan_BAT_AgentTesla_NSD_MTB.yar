
rule Trojan_BAT_AgentTesla_NSD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 37 62 30 64 31 35 66 66 2d 35 39 63 30 2d 34 30 30 37 2d 38 32 61 61 2d 65 37 34 31 31 38 36 35 33 31 63 62 } //01 00  $7b0d15ff-59c0-4007-82aa-e741186531cb
		$a_01_1 = {56 69 73 75 61 6c 5f 4e 5f 51 75 65 65 6e 73 5f 53 6f 6c 76 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Visual_N_Queens_Solver.Properties.Resources.resources
		$a_01_2 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}