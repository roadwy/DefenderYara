
rule VirTool_Win32_Obfuscator_AIJ{
	meta:
		description = "VirTool:Win32/Obfuscator.AIJ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 4d 08 51 6a 41 6a 6a 66 8b 55 08 52 e8 57 18 00 00 83 c4 10 6a 22 e8 f0 f7 ff ff 83 c4 04 6a 6e 6a a9 66 8b 45 08 50 e8 e3 1a 00 00 83 c4 0c 6a eb 8b 4d 14 51 6a 3b 8a 55 08 52 8a 45 10 50 e8 3d 00 00 00 83 c4 14 68 eb 00 00 00 68 e2 00 00 00 e8 a1 05 00 00 83 c4 08 6a 4e 6a ae } //01 00 
		$a_01_1 = {6a 00 ff 15 10 40 40 00 c7 45 f0 fb 00 00 00 0f bf 45 08 8b 4d f0 0f af c8 89 4d f0 8b 55 f0 81 c2 29 57 00 00 89 55 f0 66 8b 45 f8 50 68 fa 00 00 00 66 8b 4d 08 51 8a 55 f8 52 66 8b 45 08 50 e8 37 1b 00 00 83 c4 14 0f bf 4d 08 51 8a 55 08 52 6a 40 e8 1a 1f 00 00 83 c4 0c } //01 00 
		$a_00_2 = {45 4e 44 42 4c 4f 43 4b 64 00 00 00 63 00 00 00 72 65 74 79 6a 6b 6d 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}