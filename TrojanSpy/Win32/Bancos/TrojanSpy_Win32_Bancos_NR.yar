
rule TrojanSpy_Win32_Bancos_NR{
	meta:
		description = "TrojanSpy:Win32/Bancos.NR,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 05 00 00 "
		
	strings :
		$a_00_0 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 66 6b 69 6e 64 79 73 61 64 76 6e 71 77 33 6e 65 72 61 73 64 66 } //5 =_NextPart_2rfkindysadvnqw3nerasdf
		$a_00_1 = {44 61 64 6f 73 20 64 6f 20 69 6e 66 65 63 74 3d 2d 3d 2d 3d 2d 3d 00 00 } //5
		$a_01_2 = {4d 41 43 20 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 2e 3a 20 00 00 00 ff ff ff ff 0b 00 00 00 53 79 73 74 65 6d 44 72 69 76 65 } //5
		$a_01_3 = {63 61 72 6d 65 6c 69 74 61 2e 6f 6e 65 40 73 61 70 6f 2e 70 74 00 00 00 ff ff ff ff 07 00 00 00 67 69 7a 61 31 35 37 } //1
		$a_01_4 = {73 6d 74 70 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 00 00 00 ff ff ff ff 06 00 00 00 31 37 35 33 34 39 } //1
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=15
 
}