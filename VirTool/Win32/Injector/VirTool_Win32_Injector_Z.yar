
rule VirTool_Win32_Injector_Z{
	meta:
		description = "VirTool:Win32/Injector.Z,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 6e 6a 65 63 74 5c 72 65 6c 65 61 73 65 5c 49 6e 6a 65 63 74 2e 70 64 62 } //01 00  inject\release\Inject.pdb
		$a_01_1 = {8d 56 0c 89 46 06 c6 06 68 c6 46 05 e8 8b c3 2b d3 } //01 00 
		$a_01_2 = {83 c5 0d 89 6f 01 c6 47 0a c2 66 c7 47 0b 04 00 } //00 00 
	condition:
		any of ($a_*)
 
}