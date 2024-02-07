
rule VirTool_Win32_Injector_HY{
	meta:
		description = "VirTool:Win32/Injector.HY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 5d d4 8b 5d f8 8b 5b 08 83 c3 50 89 5d d0 89 65 cc b8 00 00 00 00 89 45 c8 8d 45 c8 50 8b 5d d0 ff 33 ff 75 d4 ff 75 e8 8b 5d d8 ff 33 ff 15 } //01 00 
		$a_03_1 = {5b 83 c3 04 5b 83 c3 04 ff 15 90 01 04 90 90 90 90 90 90 90 90 39 65 c0 74 0d 68 06 00 00 00 90 00 } //01 00 
		$a_03_2 = {ff 75 b8 68 00 00 00 00 ff 15 90 01 04 90 90 90 90 90 90 90 90 39 65 b4 74 0d 68 06 00 00 00 e8 90 00 } //01 00 
		$a_03_3 = {83 c7 04 8b 03 83 c3 04 89 07 83 c7 04 8b 5d d8 ff 33 ff 15 90 01 04 90 90 90 90 90 90 90 90 39 65 d4 74 0d 68 06 00 00 00 e8 90 00 } //01 00 
		$a_00_4 = {7e 15 } //00 00  ᕾ
	condition:
		any of ($a_*)
 
}