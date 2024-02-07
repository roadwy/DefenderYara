
rule Trojan_BAT_AgentTesla_LJC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 62 65 32 62 62 39 38 2d 38 37 62 64 2d 34 36 34 62 2d 62 33 38 30 2d 65 34 66 34 31 62 36 33 32 30 63 30 } //01 00  cbe2bb98-87bd-464b-b380-e4f41b6320c0
		$a_81_1 = {30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d } //01 00  000webhostapp.com
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_01_5 = {47 65 74 54 79 70 65 } //01 00  GetType
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}