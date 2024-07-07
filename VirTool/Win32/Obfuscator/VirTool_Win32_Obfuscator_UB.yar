
rule VirTool_Win32_Obfuscator_UB{
	meta:
		description = "VirTool:Win32/Obfuscator.UB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 06 00 07 00 00 "
		
	strings :
		$a_03_0 = {83 e8 03 68 90 01 02 40 00 48 ff d0 90 00 } //1
		$a_03_1 = {83 e8 03 68 90 01 02 40 00 68 90 01 02 40 00 48 ff d0 90 00 } //1
		$a_03_2 = {83 e8 03 68 90 01 02 40 00 68 90 01 02 40 00 68 90 01 02 40 00 48 ff d0 90 00 } //1
		$a_03_3 = {83 e8 03 68 90 01 02 40 00 68 90 01 02 40 00 68 90 01 02 40 00 68 90 01 02 40 00 48 ff d0 90 00 } //1
		$a_00_4 = {53 56 57 bb 01 00 00 00 8b 7c 24 14 50 53 51 } //1
		$a_00_5 = {00 00 00 00 00 00 00 00 50 00 4f 00 50 00 4f 00 41 00 4b 00 } //1
		$a_00_6 = {c7 85 c4 fe ff ff 9c 07 00 00 c7 85 dc fe ff ff c5 2f 02 00 c7 85 e0 fe ff ff a1 a3 0a 00 c7 85 d4 fe ff ff 74 ce 02 00 6a 04 8d 85 d4 fe ff ff 50 8d 8d c4 fe ff ff 51 e8 2b f2 ff ff 8b 95 c4 fe ff ff 8b 85 c4 fe ff ff 83 e8 01 89 85 c4 fe ff ff 85 d2 0f 84 ae 00 00 00 8b b5 e0 fe ff ff 81 c6 92 b6 a9 00 6a 76 e8 db f3 ff ff 0f b7 c8 2b f1 6a 50 e8 cf f3 ff ff 0f b7 d0 03 95 dc fe ff ff 03 d6 89 95 dc fe ff ff 8b 85 dc fe ff ff 05 53 af 00 00 8b 8d e0 fe ff ff 2b c8 89 8d e0 fe ff ff c7 85 cc fe ff ff 04 27 00 00 8b 95 cc fe ff ff 8b 85 cc fe ff ff 83 e8 01 89 85 cc fe ff ff 85 d2 74 3d 6a 43 e8 7b f3 ff ff } //3
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*3) >=6
 
}