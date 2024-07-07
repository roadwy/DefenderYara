
rule TrojanDownloader_Win32_Delf_QZ{
	meta:
		description = "TrojanDownloader:Win32/Delf.QZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {4e 2f 45 5a 54 47 68 63 53 42 78 34 56 55 55 52 63 56 58 78 74 57 74 4d 32 35 50 } //1 N/EZTGhcSBx4VUURcVXxtWtM25P
		$a_00_1 = {68 57 64 67 76 65 52 33 58 6d 6d 38 77 4a 2f 74 48 70 30 30 36 5a 6f 44 34 69 77 72 39 70 32 2b 32 74 47 64 71 31 56 6b 31 31 69 6d 2b } //1 hWdgveR3Xmm8wJ/tHp006ZoD4iwr9p2+2tGdq1Vk11im+
		$a_01_2 = {44 65 63 72 79 70 74 4d 65 73 73 61 67 65 } //1 DecryptMessage
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}