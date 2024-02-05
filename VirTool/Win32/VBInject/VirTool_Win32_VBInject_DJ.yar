
rule VirTool_Win32_VBInject_DJ{
	meta:
		description = "VirTool:Win32/VBInject.DJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 0f b6 0c 08 8b 45 c4 66 33 0c 50 ff 15 90 01 04 8b 4d a8 8b 51 0c 8b 4d e8 88 04 1a b8 01 00 00 00 03 c1 0f 80 90 00 } //01 00 
		$a_03_1 = {74 3f 66 83 38 01 75 39 8b 35 90 01 04 8b cf 81 c6 f8 00 00 00 8b 50 14 90 00 } //01 00 
		$a_03_2 = {8b 55 c0 8d 45 e8 50 8b 85 c4 fe ff ff 8d 8d ac fe ff ff 83 c2 08 6a 04 51 0f 80 90 01 04 52 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}