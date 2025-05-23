
rule VirTool_Win32_Obfuscator_ANK{
	meta:
		description = "VirTool:Win32/Obfuscator.ANK,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 03 48 20 51 e8 ?? ?? 00 00 eb 08 6a 00 ff 95 ?? ?? ff ff eb 08 6a 00 ff 95 ?? ?? ff ff 8b 95 ?? ?? ff ff 83 7a 08 00 74 } //1
		$a_03_1 = {75 08 6a 00 ff 95 ?? ?? ff ff 83 bd ?? ?? ff ff 05 75 09 83 bd ?? ?? ff ff 00 74 17 83 bd ?? ?? ff ff 05 75 09 83 bd ?? ?? ff ff 01 74 05 } //1
		$a_03_2 = {0f b6 08 83 f9 4b 0f 85 ?? ?? 00 00 8b 55 dc 0f b6 42 01 83 f8 45 0f 85 ?? ?? 00 00 8b 4d dc 0f b6 51 02 83 fa 52 0f 85 ?? ?? 00 00 8b 45 dc 0f b6 48 03 83 f9 4e 0f 85 } //1
		$a_01_3 = {8b 55 08 8b 42 04 ff d0 89 45 f8 8b 4d f4 8b 55 f8 89 11 8b 45 f4 83 c0 04 89 45 f4 eb 9b } //1
		$a_03_4 = {e8 00 00 00 00 58 2d ?? ?? 00 00 c3 64 a1 30 00 00 00 c7 80 2c 02 00 00 00 00 00 00 c3 } //1
		$a_00_5 = {2b 2f 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 00 4b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 53 68 65 6c 6c 33 32 2e 64 6c 6c 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_00_5  & 1)*1) >=1
 
}