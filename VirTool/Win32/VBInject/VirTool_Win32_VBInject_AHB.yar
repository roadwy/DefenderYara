
rule VirTool_Win32_VBInject_AHB{
	meta:
		description = "VirTool:Win32/VBInject.AHB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba 83 3d 52 d1 31 14 08 c3 } //01 00 
		$a_03_1 = {0f 77 66 8b 1c 0e 90 90 66 31 1c 0f 90 90 49 49 50 58 85 c9 7d ec 51 59 31 c9 0f 77 0f 77 e8 90 01 04 90 90 66 41 50 58 66 41 0f 77 66 41 0f 77 66 41 0f 77 90 90 3b 8d 90 01 04 75 e1 90 90 ff e0 90 00 } //01 00 
		$a_01_2 = {53 69 6c 76 65 72 65 79 65 } //00 00 
	condition:
		any of ($a_*)
 
}