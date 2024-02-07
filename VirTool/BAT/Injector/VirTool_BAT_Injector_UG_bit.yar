
rule VirTool_BAT_Injector_UG_bit{
	meta:
		description = "VirTool:BAT/Injector.UG!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {2e 72 65 73 6f 75 72 63 65 73 00 90 01 08 2d 90 01 04 2d 90 01 02 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 90 00 } //01 00 
		$a_03_1 = {15 53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70 90 01 1e 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 90 00 } //01 00 
		$a_01_2 = {00 3c 4d 6f 64 75 6c 65 3e 00 } //01 00  㰀潍畤敬>
		$a_01_3 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 } //01 00  System.CodeDom.Compiler
		$a_01_4 = {47 65 6e 65 72 61 74 65 64 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //01 00  GeneratedCodeAttribute
		$a_01_5 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //00 00  get_EntryPoint
	condition:
		any of ($a_*)
 
}