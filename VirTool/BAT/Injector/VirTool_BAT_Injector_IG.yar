
rule VirTool_BAT_Injector_IG{
	meta:
		description = "VirTool:BAT/Injector.IG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 20 4c c2 34 35 61 03 61 0a } //01 00 
		$a_00_1 = {64 00 36 00 30 00 65 00 34 00 38 00 30 00 63 00 2d 00 34 00 33 00 62 00 64 00 2d 00 34 00 61 00 62 00 37 00 2d 00 38 00 64 00 61 00 30 00 2d 00 33 00 66 00 66 00 61 00 61 00 31 00 61 00 64 00 35 00 63 00 32 00 34 00 } //00 00  d60e480c-43bd-4ab7-8da0-3ffaa1ad5c24
	condition:
		any of ($a_*)
 
}