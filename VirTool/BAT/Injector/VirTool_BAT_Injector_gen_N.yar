
rule VirTool_BAT_Injector_gen_N{
	meta:
		description = "VirTool:BAT/Injector.gen!N,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 72 6f 6d 65 4d 6c 61 75 74 72 69 56 65 74 69 72 57 74 4e 00 6e 6f 69 74 63 65 53 66 4f 77 65 69 56 70 61 6d 6e 55 74 4e } //01 00 
		$a_01_1 = {00 70 75 74 72 61 74 73 00 7a 6e 75 52 00 } //01 00 
		$a_01_2 = {1f 1f 5f 62 09 61 08 58 61 d2 9c 09 17 58 0d } //00 00 
	condition:
		any of ($a_*)
 
}