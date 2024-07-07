
rule TrojanSpy_Win32_Bancos_JW{
	meta:
		description = "TrojanSpy:Win32/Bancos.JW,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_00_0 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 66 6b 69 6e 64 79 73 61 64 76 6e 71 77 33 6e 65 72 61 73 64 66 } //5 =_NextPart_2rfkindysadvnqw3nerasdf
		$a_00_1 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 72 65 6c 72 66 6b 73 61 64 76 6e 71 69 6e 64 79 77 33 6e 65 72 61 73 64 66 } //5 =_NextPart_2relrfksadvnqindyw3nerasdf
		$a_00_2 = {3d 5f 4e 65 78 74 50 61 72 74 5f 32 61 6c 74 72 66 6b 69 6e 64 79 73 61 64 76 6e 71 77 33 6e 65 72 61 73 64 66 } //5 =_NextPart_2altrfkindysadvnqw3nerasdf
		$a_00_3 = {42 72 61 64 65 73 63 6f 20 4e 65 74 20 45 6d 70 72 65 73 61 } //5 Bradesco Net Empresa
		$a_00_4 = {5c 53 59 53 54 45 4d 33 32 5c 44 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 00 ff ff ff ff 23 00 00 00 31 32 37 2e 30 2e 30 2e 31 20 62 72 61 64 65 73 63 6f 6e 65 74 65 6d 70 72 65 73 61 2e 63 6f 6d 2e 62 72 } //1
		$a_01_5 = {6c 6f 67 73 72 6f 78 40 67 6d 61 69 6c 2e 63 6f 6d 00 00 00 ff ff ff ff 1b 00 00 00 6a 75 63 69 61 72 61 2e 61 6e 74 6f 6e 69 61 40 69 73 62 74 2e 63 6f 6d 2e 62 72 } //1
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5+(#a_00_4  & 1)*1+(#a_01_5  & 1)*1) >=21
 
}