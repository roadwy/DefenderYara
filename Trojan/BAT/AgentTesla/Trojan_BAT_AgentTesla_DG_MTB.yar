
rule Trojan_BAT_AgentTesla_DG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0c 00 00 14 00 "
		
	strings :
		$a_81_0 = {24 33 65 36 39 66 37 66 34 2d 33 65 66 30 2d 34 39 32 64 2d 38 66 33 37 2d 61 65 31 37 34 35 37 30 30 64 63 63 } //14 00  $3e69f7f4-3ef0-492d-8f37-ae1745700dcc
		$a_81_1 = {24 63 61 39 32 62 30 37 63 2d 35 38 61 34 2d 34 31 62 32 2d 38 36 61 65 2d 30 38 32 37 37 63 38 35 64 32 38 33 } //14 00  $ca92b07c-58a4-41b2-86ae-08277c85d283
		$a_81_2 = {24 32 31 35 31 65 30 62 33 2d 37 63 61 62 2d 34 38 30 66 2d 38 35 62 31 2d 34 64 66 61 33 38 65 38 62 31 32 64 } //01 00  $2151e0b3-7cab-480f-85b1-4dfa38e8b12d
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerNonUserCodeAttribute
		$a_81_4 = {54 65 78 74 5f 45 64 69 74 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Text_Editer.Properties.Resources
		$a_81_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerBrowsableAttribute
		$a_81_6 = {50 68 6f 74 6f 45 64 69 74 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  PhotoEditor.Properties.Resources
		$a_81_7 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_8 = {54 65 78 74 45 64 69 74 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //01 00  TextEditer.Properties.Resources.resources
		$a_81_9 = {54 61 72 67 65 74 46 72 61 6d 65 77 6f 72 6b 41 74 74 72 69 62 75 74 65 } //01 00  TargetFrameworkAttribute
		$a_81_10 = {67 65 74 5f 41 75 74 6f 53 63 61 6c 65 42 61 73 65 53 69 7a 65 } //01 00  get_AutoScaleBaseSize
		$a_81_11 = {47 65 74 41 73 73 65 6d 62 6c 69 65 73 } //00 00  GetAssemblies
	condition:
		any of ($a_*)
 
}