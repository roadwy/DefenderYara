
rule VirTool_Win32_Injector_IV{
	meta:
		description = "VirTool:Win32/Injector.IV,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 e2 8d b4 24 90 01 01 00 00 00 89 72 04 89 0a 8b 0d 90 01 04 89 44 24 90 01 01 ff d1 90 00 } //01 00 
		$a_03_1 = {89 e6 89 4e 0c 90 02 06 c7 46 08 00 10 00 00 90 02 08 c7 06 00 00 00 00 ff d0 83 ec 10 89 90 02 04 8b 90 02 04 89 90 02 04 89 90 02 04 89 90 02 04 e8 90 01 01 01 00 00 83 ec 08 8b 90 02 04 8b 90 00 } //01 00 
		$a_03_2 = {89 e1 89 41 04 8d 90 02 06 89 01 e8 90 01 02 ff ff 83 ec 08 89 90 02 08 89 e0 c7 00 4e 7d 40 00 e8 90 01 02 ff ff 83 ec 04 83 f8 00 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}