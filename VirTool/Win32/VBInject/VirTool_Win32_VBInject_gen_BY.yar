
rule VirTool_Win32_VBInject_gen_BY{
	meta:
		description = "VirTool:Win32/VBInject.gen!BY,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 "
		
	strings :
		$a_03_0 = {b8 ff 00 00 00 3b f0 7f 2e 81 fe 00 01 00 00 72 06 ff 15 ?? ?? ?? ?? 8b ce ff 15 ?? ?? ?? ?? 8b 4f ?? 66 89 04 71 b8 01 00 00 00 03 c6 0f 80 ?? ?? ?? ?? 8b f0 eb c9 } //1
		$a_03_1 = {b8 ff 00 00 00 66 3b f0 7f 2a 0f bf fe 81 ff 00 01 00 00 72 06 ff 15 ?? ?? ?? ?? 8b 55 d0 b8 01 00 00 00 66 03 c6 66 89 34 7a 0f 80 } //1
		$a_03_2 = {6a 01 51 56 c7 45 ?? e8 00 00 00 e8 } //1
		$a_01_3 = {6a 04 51 56 c7 45 9c 58 59 59 59 e8 } //1
		$a_01_4 = {6a 01 50 0f 80 8b 00 00 00 56 c7 45 a0 c3 00 00 00 e8 } //1
		$a_03_5 = {8d 45 e0 50 e8 ?? ?? ?? ?? 33 db 66 3d ff ff 8d 4d e4 0f 94 c3 51 f7 db e8 ?? ?? ?? ?? 33 d2 66 3d ff ff 0f 94 c2 8d 45 e8 } //1
		$a_01_6 = {45 6e 63 72 79 70 74 44 61 74 61 00 44 65 63 72 79 70 74 44 61 74 61 00 } //1 湅牣灹䑴瑡a敄牣灹䑴瑡a
		$a_01_7 = {4b 65 79 00 45 6e 63 72 79 70 74 46 69 6c 65 00 44 65 63 72 79 70 74 46 69 6c 65 00 44 65 63 72 79 70 74 42 79 74 65 00 } //1 敋y湅牣灹䙴汩e敄牣灹䙴汩e敄牣灹䉴瑹e
		$a_00_8 = {50 00 69 00 6d 00 70 00 20 00 43 00 72 00 79 00 70 00 74 00 65 00 72 00 20 00 32 00 2e 00 30 00 20 00 70 00 72 00 69 00 76 00 61 00 74 00 65 00 20 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 } //1 Pimp Crypter 2.0 private version
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1) >=3
 
}