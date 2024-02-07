
rule Trojan_BAT_AgentTesla_NNJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NNJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 2c 5b 16 13 07 16 13 08 09 6f 62 01 00 06 13 0a 11 0a 2c 1d 09 6f 64 01 00 06 6f 95 01 00 06 13 07 11 06 6f 64 01 00 06 6f 97 01 00 06 13 08 2b 1b 11 06 6f 64 01 00 06 } //01 00 
		$a_01_1 = {24 39 36 38 65 37 62 64 30 2d 30 35 30 65 2d 34 63 37 37 2d 39 36 30 37 2d 38 38 30 33 66 31 33 61 65 33 31 66 } //01 00  $968e7bd0-050e-4c77-9607-8803f13ae31f
		$a_01_2 = {4c 79 74 72 6f 2e 57 69 6e 64 6f 77 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  Lytro.Windows.Properties.Resources.resources
		$a_01_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_01_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}