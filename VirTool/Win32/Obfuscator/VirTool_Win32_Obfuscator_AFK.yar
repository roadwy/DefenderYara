
rule VirTool_Win32_Obfuscator_AFK{
	meta:
		description = "VirTool:Win32/Obfuscator.AFK,SIGNATURE_TYPE_PEHSTR_EXT,14 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b c1 8b 10 8b 40 04 83 e8 08 83 c1 08 d1 e8 74 90 01 01 89 45 08 0f b7 01 8b f8 81 e7 00 f0 00 00 bb 00 30 00 00 66 3b fb 75 11 8b 7d 0c 2b 7d 10 25 ff 0f 00 00 03 c2 03 c6 01 38 41 41 ff 4d 08 90 00 } //1
		$a_02_1 = {40 23 c1 8d b4 90 01 05 8a 16 89 45 f8 0f b6 c2 03 45 fc 23 c1 89 45 fc 8d 84 90 01 05 8a 18 88 10 88 1e 0f b6 00 0f b6 d3 03 d0 81 e2 ff 00 00 80 79 90 01 01 4a 81 ca 00 ff ff ff 42 90 00 } //1
		$a_03_2 = {47 65 74 50 c7 90 01 02 72 6f 63 41 c7 90 01 02 64 64 72 65 c7 90 01 02 73 73 00 00 c7 90 01 02 56 69 72 74 c7 90 01 02 75 61 6c 50 c7 90 01 02 72 6f 74 65 c7 90 01 02 63 74 00 00 e8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}