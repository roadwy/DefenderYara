
rule VirTool_Win32_Injector_BZ{
	meta:
		description = "VirTool:Win32/Injector.BZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 56 8d 0c 06 e8 90 01 04 30 01 83 c4 04 46 3b 90 01 01 7c e9 90 00 } //02 00 
		$a_02_1 = {f6 d1 32 08 80 f1 74 90 01 01 88 08 90 00 } //01 00 
		$a_00_2 = {c6 00 e9 ff 06 8b 06 2b f8 } //01 00 
		$a_00_3 = {6a 00 ff 70 54 ff 75 0c ff 70 34 } //00 00 
	condition:
		any of ($a_*)
 
}