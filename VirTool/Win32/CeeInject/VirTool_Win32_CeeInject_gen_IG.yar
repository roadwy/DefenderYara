
rule VirTool_Win32_CeeInject_gen_IG{
	meta:
		description = "VirTool:Win32/CeeInject.gen!IG,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c0 02 32 d1 3d 90 01 02 00 00 88 90 90 90 01 02 40 00 76 e8 33 c0 8a 88 90 01 02 40 00 40 f6 d1 88 88 90 01 02 40 00 3d 90 01 02 00 00 76 ea 8a 15 90 01 02 40 00 b9 01 00 00 00 b8 90 01 02 40 00 8a 18 83 c1 02 32 da 88 18 83 c0 02 81 f9 90 01 02 00 00 76 ec 33 c0 b1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}