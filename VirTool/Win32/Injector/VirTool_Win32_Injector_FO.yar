
rule VirTool_Win32_Injector_FO{
	meta:
		description = "VirTool:Win32/Injector.FO,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 32 37 2e 30 2e 30 2e 31 3a 38 30 38 30 } //01 00 
		$a_01_1 = {4e 4f 4b 49 41 4e 39 35 2f 57 45 42 } //01 00 
		$a_01_2 = {68 74 74 70 5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } //01 00 
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00 
		$a_00_4 = {fb f0 bf 5f 97 0f 2c 38 } //01 00 
		$a_00_5 = {6a 40 68 00 10 00 00 68 00 28 00 00 6a 00 ff } //00 00 
		$a_00_6 = {5d 04 00 00 } //6e 39 
	condition:
		any of ($a_*)
 
}