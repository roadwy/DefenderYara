
rule VirTool_Win32_CeeInject_gen_GZ{
	meta:
		description = "VirTool:Win32/CeeInject.gen!GZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3e 8b 48 3c a1 90 02 20 36 03 04 24 90 02 10 3e 0f b7 40 06 83 f8 90 01 01 74 01 c3 90 00 } //01 00 
		$a_03_1 = {0f b6 54 32 ff 33 d3 88 54 30 ff 4b 85 db 75 90 01 01 46 4f 75 90 01 01 be 90 01 04 b8 90 01 04 bb 90 01 04 30 18 4b 85 db 75 f9 40 4e 75 f0 8d 05 90 02 10 ff d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}