
rule VirTool_Win32_VBInject_QO{
	meta:
		description = "VirTool:Win32/VBInject.QO,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {b9 09 02 00 00 33 c0 8d bd b8 f7 ff ff 33 f6 f3 ab b9 09 01 00 00 8d bd 0c f3 ff ff f3 ab b9 09 01 00 00 8d bd e8 ee ff ff 56 6a 02 f3 ab 89 75 e4 } //01 00 
		$a_01_1 = {8b d0 8d 8d b4 f7 ff ff ff d7 8d 8d b4 f7 ff ff 8d 95 88 f7 ff ff 6a 01 8d 85 98 f7 ff ff 89 8d 40 f7 ff ff 52 50 8d 8d 78 f7 ff ff 56 } //01 00 
		$a_03_2 = {8b 95 4c f7 ff ff 89 55 c8 c7 45 fc 06 00 00 00 83 7d c8 00 0f 84 90 01 04 c7 45 fc 07 00 00 00 c7 85 98 f7 ff ff 24 04 00 00 c7 45 fc 08 00 00 00 8d 85 98 f7 ff ff 90 00 } //01 00 
		$a_01_3 = {c7 45 fc 0d 00 00 00 8b 85 a0 f7 ff ff 89 45 c4 c7 45 fc 0e 00 00 00 8b 55 d4 8d 4d c0 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}