
rule VirTool_O97M_Empire_E_MTB{
	meta:
		description = "VirTool:O97M/Empire.E!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {65 78 65 63 28 62 61 73 65 36 34 2e 62 36 34 64 65 63 6f 64 65 28 27 } //01 00 
		$a_00_1 = {70 79 74 68 6f 6e } //01 00 
		$a_00_2 = {77 69 6e 6d 67 6d 74 73 3a 5c 5c 2e 5c 72 6f 6f 74 5c 63 69 6d 76 32 } //01 00 
		$a_02_3 = {2e 53 68 6f 77 57 69 6e 64 6f 77 90 02 05 3d 90 02 05 30 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}