
rule VirTool_BAT_Injector_IY_bit{
	meta:
		description = "VirTool:BAT/Injector.IY!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 8c 27 00 00 01 13 90 01 02 11 90 01 02 11 90 01 03 11 90 01 01 28 90 01 01 00 00 0a 91 61 9c 11 90 01 01 17 58 13 90 01 01 11 90 01 01 11 90 01 01 31 90 00 } //01 00 
		$a_01_1 = {50 6f 77 65 72 65 64 42 79 41 74 74 72 69 62 75 74 65 00 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 41 74 74 72 69 62 75 74 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}