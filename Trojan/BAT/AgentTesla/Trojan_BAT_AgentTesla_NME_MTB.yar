
rule Trojan_BAT_AgentTesla_NME_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 35 64 36 36 33 61 64 32 2d 64 36 65 32 2d 34 33 62 66 2d 61 34 62 61 2d 33 39 33 38 33 33 33 38 33 36 34 62 } //01 00  $5d663ad2-d6e2-43bf-a4ba-39383338364b
		$a_01_1 = {6f 0a 00 00 0a 0d 09 6f 37 00 00 0a 17 8d 09 00 00 01 25 16 1f 26 9d 6f 38 00 00 0a } //01 00 
		$a_01_2 = {43 6c 6f 63 6b 74 6f 77 65 72 73 43 75 72 73 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ClocktowersCurse.Properties.Resources.resources
		$a_01_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_01_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_01_5 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_01_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_8 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_9 = {53 70 6c 69 74 } //00 00  Split
	condition:
		any of ($a_*)
 
}