
rule VirTool_Win32_Obfuscator_CAP_{
	meta:
		description = "VirTool:Win32/Obfuscator.CAP!!ObfuscatorCap.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 09 00 00 "
		
	strings :
		$a_03_0 = {fc ad 85 c0 74 ?? 40 74 ?? 48 03 45 04 8b d0 ad 56 8b c8 8b f2 f3 a4 5e eb } //1
		$a_01_1 = {8b 75 f8 03 f1 4e c1 e9 03 8b d1 8b 5d c0 56 51 b9 08 00 00 00 8a 07 32 c3 88 06 47 2b f2 49 75 f4 } //1
		$a_01_2 = {8b 75 f8 49 03 f1 03 f8 41 2b f9 8a 07 32 c3 88 06 47 4e 49 75 f5 } //1
		$a_01_3 = {75 f7 6a 00 8d 45 ec 50 ff 75 f8 ff 75 c4 ff 75 fc ff 55 cc } //1
		$a_01_4 = {72 04 51 ff 55 0c 6a 01 68 00 20 00 00 ff 75 e8 ff 75 e4 ff 55 10 85 c0 75 0e } //1
		$a_01_5 = {03 45 d8 50 ff 55 28 8b d8 8b 47 10 85 c0 75 0a 8b 07 85 c0 } //1
		$a_01_6 = {8b 06 85 c0 74 33 a9 00 00 00 f0 74 07 25 ff ff 00 00 eb 05 03 45 d8 40 40 50 53 ff 55 24 } //1
		$a_03_7 = {8b 74 24 28 8b 7c 24 30 bd 03 00 00 00 31 c0 31 db ac 3c 11 76 ?? 2c 11 3c 04 73 ?? 89 c1 eb ?? 05 ff 00 00 00 } //1
		$a_00_8 = {73 73 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 00 56 69 72 74 75 61 6c 46 72 65 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1+(#a_00_8  & 1)*1) >=5
 
}