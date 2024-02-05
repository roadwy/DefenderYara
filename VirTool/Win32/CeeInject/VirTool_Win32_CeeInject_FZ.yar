
rule VirTool_Win32_CeeInject_FZ{
	meta:
		description = "VirTool:Win32/CeeInject.FZ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 fb 05 47 86 c8 61 8b d8 83 e3 03 8b 1c 9e } //01 00 
		$a_03_1 = {57 bf b0 1e 04 00 68 90 01 04 ff d6 4f 90 03 02 02 75 f6 33 ff e8 90 00 } //01 00 
		$a_01_2 = {c7 45 f0 75 73 65 72 8d 45 f0 50 66 c7 45 f4 33 32 c6 45 f6 00 ff d3 } //01 00 
		$a_03_3 = {6a 07 6a ff be 01 00 00 00 c7 45 fc 00 00 00 00 ff 15 90 01 04 85 c0 78 08 83 7d fc 00 75 02 33 f6 6a 00 6a 00 6a 11 ff 15 90 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 5c 
	condition:
		any of ($a_*)
 
}