
rule VirTool_Win32_Obfuscator_AMM{
	meta:
		description = "VirTool:Win32/Obfuscator.AMM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {33 c0 8b ce 03 c8 8a 09 88 0c 02 8d 48 01 33 4b 04 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 8d 48 01 33 0b 51 33 c9 8a 0c 02 5f 2b cf 88 0c 02 40 ff 8d 0c fe ff ff 75 cb } //1
		$a_01_1 = {50 ff 55 d0 8b d8 53 ff 55 cc 89 45 e8 46 83 ff 64 76 ca e8 00 00 00 00 58 } //1
		$a_01_2 = {75 f2 8b 55 ec 03 d0 8a 12 3a 55 84 75 e6 8b 55 ec 03 d0 42 8a 12 3a 55 85 75 d9 } //1
		$a_01_3 = {c6 45 ab 56 c6 45 ac 69 c6 45 ad 72 c6 45 ae 74 c6 45 af 75 c6 45 b0 61 c6 45 b1 6c c6 45 b2 41 c6 45 b3 6c c6 45 b4 6c c6 45 b5 6f c6 45 b6 63 c6 45 b7 00 8d 45 ab 50 53 ff 55 e8 } //1
		$a_01_4 = {eb 28 ac d1 e8 74 4d 11 c9 eb 1c 91 48 c1 e0 08 ac e8 2c 00 00 00 3d 00 7d 00 00 73 0a 80 fc 05 73 06 83 f8 7f 77 02 } //1
		$a_01_5 = {8b 55 f4 0f b6 14 02 33 57 04 8b 4d f4 88 14 01 40 4e 75 ec 8b 07 89 45 ec e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}