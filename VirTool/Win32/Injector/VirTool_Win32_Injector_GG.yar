
rule VirTool_Win32_Injector_GG{
	meta:
		description = "VirTool:Win32/Injector.GG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {b8 4b 0a 0f 51 8a 0d 34 30 40 00 f7 ef c1 fa 0a 8b c2 c1 e8 1f 8a 94 02 20 30 40 00 32 d1 80 fa f2 88 94 35 04 e2 ff ff 77 09 fe ca 88 94 35 04 e2 ff ff } //1
		$a_01_1 = {75 b3 68 10 65 f5 40 6a 00 8d 8d 2c e2 ff ff ff d1 83 c4 08 eb 9f } //1
		$a_01_2 = {9b 1a 85 30 9b 1a 86 3a 9b 1a 87 2f 9b 1a 80 33 9b 1a 81 3a 9b 1a 82 31 9b 1a 83 68 9b 1a bc 6f 9b 1a bd 73 9b 1a be 39 9b 1a bf 31 9b 1a b8 31 d5 02 b9 9b } //1
		$a_01_3 = {c6 45 d8 6b c6 45 d9 65 c6 45 da 72 c6 45 db 6e c6 45 dc 65 c6 45 dd 6c c6 45 de 33 c6 45 df 32 c6 45 e0 2e c6 45 e1 64 c6 45 e2 6c c6 45 e3 6c 88 5d e4 } //1
		$a_01_4 = {3b 94 da 55 a3 a3 a3 73 5d 3b 94 da 57 a3 a3 a3 09 5d 3b 94 da 51 a3 a3 a3 12 5d 3b 94 da 53 a3 a3 a3 0d 5d 3b d6 c2 4d a3 a3 a3 a3 0a b5 d2 } //1
		$a_01_5 = {66 c7 85 08 ff ff ff 2e 00 66 c7 85 0a ff ff ff 54 00 66 c7 85 0c ff ff ff 4d 00 66 c7 85 0e ff ff ff 50 00 66 89 9d 10 ff ff ff ff 55 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}