
rule VirTool_Win32_Injector_HF{
	meta:
		description = "VirTool:Win32/Injector.HF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6b c9 2c 8b 3d 90 01 04 2b d1 89 15 90 01 04 8b 8c 06 90 01 04 0f b6 d2 2b fa 81 c1 90 01 04 83 ef 04 89 3d 90 01 04 89 0d 90 01 04 89 8c 06 90 01 04 83 c0 04 3d 90 01 04 72 90 00 } //01 00 
		$a_03_1 = {2b d6 83 ea 3b 8b cf 2b ce 83 e9 3b 0f b6 f2 8b e9 2b ee 83 ed 04 85 c0 a3 90 01 04 89 15 90 01 04 89 0d 90 01 04 89 2d 90 01 04 0f 84 90 01 04 0f b6 d3 2b ca 68 90 01 04 83 e9 04 50 89 0d 90 01 04 ff 15 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}