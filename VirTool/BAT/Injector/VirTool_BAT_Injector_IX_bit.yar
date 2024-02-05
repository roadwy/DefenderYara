
rule VirTool_BAT_Injector_IX_bit{
	meta:
		description = "VirTool:BAT/Injector.IX!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 00 0a 91 61 9c 11 90 01 01 17 58 13 90 01 01 11 90 01 01 11 90 01 01 31 90 00 } //01 00 
		$a_00_1 = {09 4c 00 6f 00 61 00 64 00 00 15 45 00 6e 00 74 00 72 00 79 00 70 00 6f 00 69 00 6e 00 74 00 00 } //01 00 
		$a_03_2 = {2e 64 6c 6c 00 53 74 72 43 6d 70 4c 6f 67 69 63 61 6c 57 00 73 31 00 73 32 00 73 68 6c 77 61 70 69 2e 64 6c 6c 00 5f 41 36 90 02 50 5f 41 37 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}