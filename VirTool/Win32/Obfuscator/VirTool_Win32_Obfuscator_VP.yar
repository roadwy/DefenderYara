
rule VirTool_Win32_Obfuscator_VP{
	meta:
		description = "VirTool:Win32/Obfuscator.VP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 c2 f8 4e 75 fa 5e 8a ca d2 c8 c3 } //1
		$a_01_1 = {80 c2 f8 4e 75 fa 5e 8a ca d2 c0 c3 } //1
		$a_01_2 = {73 fa 0f b6 c0 8b 44 c1 04 e9 52 ff ff ff d0 e9 3a ca 73 fa 0f b6 c9 8b 04 c8 eb 81 d0 e9 3a ca 73 fa 0f b6 c9 8b 04 c8 eb ae 32 c0 5f c9 c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule VirTool_Win32_Obfuscator_VP_2{
	meta:
		description = "VirTool:Win32/Obfuscator.VP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {32 55 fd 8a 0f ff d0 88 07 fe 45 ff 8a 45 ff 3a 06 72 c4 0f b7 46 0a } //1
		$a_01_1 = {8a 56 08 8a 4e 02 ff d0 88 46 02 33 c0 66 89 46 0e 0f b7 46 06 } //1
		$a_01_2 = {8a 56 04 8a 4e 01 ff d0 88 46 01 33 c0 66 89 46 0c ff 4d f8 47 0f 85 25 ff ff ff 5b b0 01 eb 30 } //1
		$a_03_3 = {8b f0 85 f6 74 21 56 ff 15 90 01 04 83 f8 01 75 0e 6a 00 ff 15 90 01 04 50 e8 de fe ff ff 90 00 } //1
		$a_03_4 = {88 5d f8 c7 45 a8 30 00 00 00 c7 45 ac 03 00 00 00 c7 45 b0 90 01 04 89 5d b4 89 5d b8 89 45 bc ff d7 90 00 } //1
		$a_03_5 = {8d 5f 15 89 4c 24 18 8d 44 24 08 50 8b 43 fc 03 44 24 18 6a 40 ff 33 50 ff 15 90 01 04 83 f8 01 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}