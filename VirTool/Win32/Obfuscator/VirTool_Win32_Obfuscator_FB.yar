
rule VirTool_Win32_Obfuscator_FB{
	meta:
		description = "VirTool:Win32/Obfuscator.FB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 1c 61 c2 08 00 55 1c 8b ec 83 83 28 80 65 ff 80 53 56 57 00 6a 01 33 f6 81 7d 0c d8 70 7c e0 5b 1c 89 75 f8 cc 5d f0 06 e8 81 ec 03 dc 00 1e f4 73 07 6a 02 e9 41 63 08 38 8b 7d a8 b9 36 1f ce 10 b8 0c 04 0a 83 01 ca ff f3 ab 8b 45 10 cc 4d 14 63 89 0c 03 c1 78 0a d8 1d 5e 0c 33 30 c9 3b 16 0f 84 13 a3 31 79 1c 0f b6 38 c1 e6 61 0b f7 40 41 86 37 83 f9 05 59 33 7c df 52 20 df 2c 84 7d 70 1c 0c 0f 86 ef 07 50 eb 50 03 82 5b cc bc f4 30 f8 c3 9e 08 83 e7 1d 9c e0 04 06 c7 81 fa 34 e0 01 3c 8d 34 1a 73 21 b5 22 55 be 07 24 4d 41 18 c1 e1 08 cd e2 86 b0 cb 40 89 1e c7 a9 8b 06 21 da c1 eb fc 0f af 18 d8 39 5d 3e 83 80 67 01 50 bf 0a 82 b0 b0 2b f8 59 0c c1 ef 05 03 b2 d3 c7 6c 45 ff b5 e8 0a 82 3e 97 03 08 8d 04 40 28 c8 0a 82 3d f8 07 0a 84 30 d8 88 38 } //00 00 
	condition:
		any of ($a_*)
 
}