
rule Trojan_BAT_Stelega_DB_MTB{
	meta:
		description = "Trojan:BAT/Stelega.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {50 6f 77 65 72 50 6f 69 6e 74 5f 54 6f 6f 6c 73 2e 42 61 69 64 75 2e 72 65 73 6f 75 72 63 65 73 } //01 00  PowerPoint_Tools.Baidu.resources
		$a_81_1 = {50 6f 77 65 72 50 6f 69 6e 74 5f 54 6f 6f 6c 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  PowerPoint_Tools.Resources
		$a_81_2 = {50 6f 77 65 72 50 6f 69 6e 74 20 54 6f 6f 6c 73 } //01 00  PowerPoint Tools
		$a_81_3 = {53 6d 75 67 67 6c 65 64 4d 65 74 68 6f 64 52 65 74 75 72 6e 4d 65 73 73 61 67 65 } //01 00  SmuggledMethodReturnMessage
		$a_81_4 = {53 74 61 74 69 63 41 72 72 61 79 49 6e 69 74 54 79 70 65 53 69 7a 65 } //01 00  StaticArrayInitTypeSize
		$a_81_5 = {45 6e 74 65 72 20 6e 65 77 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 73 74 72 69 6e 67 3a } //01 00  Enter new connection string:
		$a_81_6 = {44 65 62 75 67 67 65 72 41 74 74 61 63 68 65 64 } //01 00  DebuggerAttached
		$a_81_7 = {5f 4c 61 6d 62 64 61 24 5f 5f } //00 00  _Lambda$__
	condition:
		any of ($a_*)
 
}