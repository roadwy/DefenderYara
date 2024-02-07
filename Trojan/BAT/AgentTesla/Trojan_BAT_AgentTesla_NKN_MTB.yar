
rule Trojan_BAT_AgentTesla_NKN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 31 63 32 65 35 66 39 65 2d 39 35 38 62 2d 34 62 33 36 2d 38 30 62 33 2d 63 37 39 64 39 64 32 61 39 36 35 37 } //01 00  $1c2e5f9e-958b-4b36-80b3-c79d9d2a9657
		$a_01_1 = {44 50 72 6f 63 65 73 73 6f 72 53 45 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  DProcessorSE.Properties.Resources.resources
		$a_01_2 = {41 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 3d 00 3d } //01 00 
		$a_01_3 = {44 00 47 00 53 00 20 00 48 00 6f 00 6d 00 65 00 53 00 6f 00 75 00 72 00 63 00 65 00 20 00 32 00 30 00 30 00 39 } //01 00 
		$a_01_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}