
rule VirTool_Win32_VBInject_QL{
	meta:
		description = "VirTool:Win32/VBInject.QL,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d7 56 6a 02 6a 01 8d 4d 90 56 51 6a 10 68 80 08 00 00 ff d7 8b 55 dc 83 c4 38 8d 45 d4 52 50 } //01 00 
		$a_01_1 = {89 85 68 ff ff ff 8b 45 90 89 9d 60 ff ff ff b9 02 00 00 00 8b 58 14 8d 95 60 ff ff ff 2b cb 8b 58 0c c1 e1 04 03 cb } //01 00 
		$a_01_2 = {8b 85 3c ff ff ff 89 b5 34 ff ff ff c7 85 2c ff ff ff 02 00 00 00 83 c4 1c 8b 48 14 8d 95 2c ff ff ff c1 e1 04 } //01 00 
		$a_01_3 = {89 85 a4 fe ff ff 8b 85 3c ff ff ff b9 09 00 00 00 c7 85 9c fe ff ff 03 00 00 00 2b 48 14 8d 95 9c fe ff ff c1 e1 04 03 48 0c ff d6 } //01 00 
		$a_01_4 = {81 e1 ff 00 00 00 ff d3 8b 0d 88 d0 40 00 c1 e6 08 03 f1 88 04 3e 66 8b 0d 4c d0 40 00 66 a1 4e d0 40 00 66 83 c1 01 } //00 00 
	condition:
		any of ($a_*)
 
}