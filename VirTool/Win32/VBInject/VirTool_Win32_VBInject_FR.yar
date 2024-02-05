
rule VirTool_Win32_VBInject_FR{
	meta:
		description = "VirTool:Win32/VBInject.FR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c8 89 4d c8 c7 45 fc 0a 00 00 00 8b 45 c8 89 45 9c 81 7d 9c 00 01 00 00 73 09 83 a5 7c ff ff ff 00 eb 0b } //01 00 
		$a_03_1 = {66 0f b6 08 8b 85 90 01 02 ff ff 8b 95 90 01 02 ff ff 66 33 0c 42 90 00 } //01 00 
		$a_01_2 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}