
rule VirTool_Win32_VBInject_AEU{
	meta:
		description = "VirTool:Win32/VBInject.AEU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4b 61 6b 61 62 61 5c 55 6e 77 65 6c 6c 5c 54 72 69 6d 6d 69 6e 67 73 5c 49 6b 61 6c 65 5c 56 42 36 2e 4f 4c 42 } //01 00 
		$a_01_1 = {4d 65 74 61 6d 6f 72 70 68 6f 75 73 30 } //01 00 
		$a_01_2 = {48 75 73 62 61 6e 64 6c 65 73 73 36 } //00 00 
		$a_00_3 = {78 b2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_VBInject_AEU_2{
	meta:
		description = "VirTool:Win32/VBInject.AEU,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 05 00 00 00 c7 85 5c ff ff ff 38 d5 03 00 c7 85 60 ff ff ff 01 00 00 00 c7 45 c4 00 00 00 00 eb 12 8b 45 c4 03 85 60 ff ff ff 0f 80 d2 03 00 00 89 45 c4 8b 4d c4 3b 8d 5c ff ff ff 0f 8f 20 01 00 00 } //01 00 
		$a_01_1 = {c7 04 ca 8c 63 23 82 c7 44 ca 04 65 16 a4 ba 8b 58 14 8b 50 0c b9 ea 01 00 00 2b cb c7 04 ca 0d 2b 4b ee c7 44 ca 04 39 21 57 e7 } //01 00 
		$a_01_2 = {c7 04 d7 f6 c2 d4 3d c7 44 d7 04 fe a0 4c b9 8b 58 14 8b 78 0c ba 7e 01 00 00 2b d3 c7 04 d7 37 4b 5d 4f c7 44 d7 04 f6 3c 31 77 } //00 00 
		$a_00_3 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}