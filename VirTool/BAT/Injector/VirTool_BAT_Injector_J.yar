
rule VirTool_BAT_Injector_J{
	meta:
		description = "VirTool:BAT/Injector.J,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {20 f8 00 00 00 d6 6a 13 90 01 01 16 12 90 01 01 7c 90 01 04 7b 90 01 04 17 da 13 2e 13 90 01 01 38 90 00 } //02 00 
		$a_01_1 = {20 50 45 00 00 6a fe 01 } //01 00 
		$a_03_2 = {11 05 02 11 05 91 90 02 02 61 90 00 } //01 00 
		$a_01_3 = {04 20 00 01 00 00 d6 b5 10 02 04 16 32 f2 } //01 00 
		$a_00_4 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}