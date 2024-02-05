
rule VirTool_Win32_VBInject_RY{
	meta:
		description = "VirTool:Win32/VBInject.RY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 51 53 ff 52 2c 3b c6 db e2 7d } //01 00 
		$a_03_1 = {88 04 3a 8b 45 dc e9 90 01 02 00 00 90 00 } //01 00 
		$a_02_2 = {6a 01 52 56 ff 15 90 01 02 40 00 6a 01 ff 15 90 01 02 40 00 8d 55 98 8d 4d bc c7 45 a0 90 01 02 40 00 c7 45 98 08 00 00 00 ff 15 90 01 02 40 00 8b 4d ec 56 90 00 } //01 00 
		$a_03_3 = {b9 b8 00 00 00 89 45 ec 89 45 e8 90 01 05 50 e8 90 01 02 00 00 8b 45 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}