
rule VirTool_Win32_Obfuscator_ADP{
	meta:
		description = "VirTool:Win32/Obfuscator.ADP,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {b1 11 81 0d 90 01 08 f6 e9 8a 4c 24 90 01 01 0f b6 c0 81 0d 90 01 08 0f b6 c9 81 15 90 01 08 99 90 00 } //01 00 
		$a_01_1 = {61 73 65 65 73 4d 61 79 6f 72 79 65 20 00 } //01 00  獡敥䵳祡牯敹 
		$a_01_2 = {43 6f 6e 65 4a 75 6a 75 6c 6f 6f 70 44 65 } //01 00  ConeJujuloopDe
		$a_03_3 = {b8 66 89 68 98 c7 05 90 01 08 89 45 e4 c7 45 d0 90 01 04 81 90 00 } //01 00 
		$a_01_4 = {c7 45 d0 5b 84 54 99 b8 68 89 a9 98 89 45 d4 } //00 00 
		$a_00_5 = {78 } //ad 01  x
	condition:
		any of ($a_*)
 
}
rule VirTool_Win32_Obfuscator_ADP_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ADP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 12 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 fb 03 fa 88 9d 90 01 02 ff ff 8a 1f 88 1e 88 07 33 db 8a 1e 90 00 } //01 00 
		$a_01_1 = {8b 5d 10 03 fb 8a 1f 88 1e 88 0f 33 db 8a 1e } //01 00 
		$a_03_2 = {0f b6 c9 8d 34 39 8a 0e 02 d1 88 95 90 01 04 0f b6 d2 03 fa 8a 17 90 00 } //01 00 
		$a_01_3 = {0f b6 d2 8d 3c 1a 8a 17 88 16 88 07 33 d2 8a 16 } //01 00 
		$a_01_4 = {03 d1 8b 4d 10 81 e2 ff 00 00 00 8a 14 0a 8b 4d 08 30 14 08 } //01 00 
		$a_01_5 = {03 c3 25 ff 00 00 00 8a 14 10 8b 45 08 30 14 01 } //01 00 
		$a_01_6 = {03 c2 25 ff 00 00 00 8a 14 18 8b 45 08 30 14 01 } //01 00 
		$a_01_7 = {03 c3 25 ff 00 00 00 8a 14 10 8b 45 08 8a 1c 01 32 da } //01 00 
		$a_01_8 = {03 c2 8a 14 31 25 ff 00 00 00 8a 04 18 32 d0 } //01 00 
		$a_03_9 = {4a 88 07 89 95 90 01 04 33 d2 8a 16 8b 75 08 90 00 } //01 00 
		$a_01_10 = {03 d9 8b 4d 10 81 e3 ff 00 00 00 8a 1c 0b 8b 4d 08 30 1c 08 } //01 00 
		$a_01_11 = {03 d9 8b 4d 08 81 e3 ff 00 00 00 8a 14 13 8a 1c 08 32 da } //01 00 
		$a_03_12 = {03 d1 81 e2 ff 00 00 00 8a 0c 1a 8a 14 30 90 02 20 32 d1 90 00 } //01 00 
		$a_01_13 = {0f b6 d2 8d 3c 1a 8a 17 88 16 33 d2 88 0f 8a 16 8b 75 08 } //01 00 
		$a_01_14 = {8b 55 10 8d 34 11 8a 0e 02 d9 0f b6 fb 03 fa } //02 00 
		$a_03_15 = {8b 75 10 03 f0 8a 06 02 d8 0f b6 fb 88 9d 90 01 04 8b 5d 10 03 fb 8a 1f 88 1e 88 07 33 db 8a 1e 8b 75 10 90 00 } //01 00 
		$a_01_16 = {03 c2 8b 55 10 25 ff 00 00 00 8a 14 10 8b 45 08 30 14 01 } //01 00 
		$a_03_17 = {8b 55 10 8d 3c 10 8a 07 8a 95 90 01 04 02 d0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}