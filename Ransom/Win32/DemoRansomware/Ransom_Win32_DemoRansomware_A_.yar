
rule Ransom_Win32_DemoRansomware_A_{
	meta:
		description = "Ransom:Win32/DemoRansomware.A!!DemoRansomware.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 65 6e 63 72 79 70 74 65 64 21 00 2e 70 64 66 00 00 00 00 2e 77 61 76 00 00 00 00 2e 74 78 74 00 00 00 00 2e 6a 70 67 00 00 00 00 2e 62 6d 70 } //1
		$a_01_1 = {3c 2f 68 32 3e 3c 69 6d 67 20 77 69 64 74 68 3d 38 30 30 20 68 65 69 67 68 74 3d 36 30 30 20 73 72 63 3d 22 68 65 6c 70 5f 64 65 63 72 79 70 74 } //1 </h2><img width=800 height=600 src="help_decrypt
		$a_01_2 = {7a 79 ee db f8 a0 df d1 23 9e f6 d5 51 36 cd dd 15 ba ee 72 39 b8 5d 8f b5 c5 63 d1 50 9a de f9 40 00 00 00 00 00 00 00 00 1e c8 f7 a5 86 fd d8 } //1
		$a_01_3 = {8b 54 24 0c 8b 4c 24 04 85 d2 74 69 33 c0 8a 44 24 08 84 c0 75 16 81 fa 80 00 00 00 72 0e 83 3d 70 52 41 00 00 74 05 e9 86 3f 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}