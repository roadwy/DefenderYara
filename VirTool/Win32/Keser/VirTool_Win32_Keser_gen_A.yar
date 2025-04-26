
rule VirTool_Win32_Keser_gen_A{
	meta:
		description = "VirTool:Win32/Keser.gen!A,SIGNATURE_TYPE_PEHSTR,1b 00 19 00 0b 00 00 "
		
	strings :
		$a_01_0 = {66 8b 43 06 8b 74 24 14 57 50 8d 46 f2 50 8d 43 08 50 e8 b6 ff ff ff 83 25 68 15 01 00 00 6a 08 } //4
		$a_01_1 = {5a 83 c6 f8 3b f2 89 74 24 18 7e 5b 8d 34 1a 83 c9 ff 8b fe 33 c0 f2 ae f7 d1 49 } //4
		$a_01_2 = {8b e9 81 fd e8 03 00 00 7f 42 a1 68 15 01 00 8b fe 6b c0 64 05 80 15 01 00 83 c9 ff } //4
		$a_01_3 = {89 44 24 14 33 c0 f2 ae f7 d1 2b f9 8d 54 2a 01 8b c1 8b f7 8b 7c 24 14 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 ff 05 68 15 01 00 3b 54 24 18 7c a5 5f 5e 5d 5b } //4
		$a_01_4 = {0f bf 44 24 0c 56 33 f6 39 74 24 0c 7e 1a 50 e8 d2 ff ff ff 8b d0 8b 4c 24 08 03 ce c1 fa 08 30 11 46 3b 74 24 0c 7c e6 } //6
		$a_01_5 = {5a 77 43 72 65 61 74 65 46 69 6c 65 } //1 ZwCreateFile
		$a_01_6 = {5a 77 43 6c 6f 73 65 } //1 ZwClose
		$a_01_7 = {5a 77 51 75 65 72 79 56 61 6c 75 65 4b 65 79 } //1 ZwQueryValueKey
		$a_01_8 = {5a 77 53 65 74 56 61 6c 75 65 4b 65 79 } //1 ZwSetValueKey
		$a_01_9 = {5a 77 43 72 65 61 74 65 4b 65 79 } //1 ZwCreateKey
		$a_01_10 = {4b 65 53 65 72 76 69 63 65 44 65 73 63 72 69 70 74 6f 72 54 61 62 6c 65 } //1 KeServiceDescriptorTable
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*4+(#a_01_3  & 1)*4+(#a_01_4  & 1)*6+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=25
 
}