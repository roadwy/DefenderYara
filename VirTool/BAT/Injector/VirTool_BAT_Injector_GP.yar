
rule VirTool_BAT_Injector_GP{
	meta:
		description = "VirTool:BAT/Injector.GP,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {2e 73 61 6f 6a 6f 73 65 2e 50 72 6f 70 65 72 74 69 65 73 00 } //0a 00 
		$a_01_1 = {74 72 6f 69 61 00 } //01 00 
		$a_01_2 = {24 33 39 63 63 66 38 62 61 2d 66 62 38 34 2d 34 32 62 35 2d 61 37 64 62 2d 65 62 30 32 61 36 32 61 38 36 36 36 00 } //01 00 
		$a_01_3 = {24 37 61 62 32 64 61 30 66 2d 36 31 34 31 2d 34 39 63 30 2d 38 36 31 61 2d 34 66 63 61 38 62 61 61 66 61 62 62 00 } //00 00 
		$a_00_4 = {5d 04 00 00 9f 66 03 80 5c 23 00 } //00 a0 
	condition:
		any of ($a_*)
 
}