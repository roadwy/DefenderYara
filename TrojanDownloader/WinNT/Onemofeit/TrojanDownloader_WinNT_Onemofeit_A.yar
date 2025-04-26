
rule TrojanDownloader_WinNT_Onemofeit_A{
	meta:
		description = "TrojanDownloader:WinNT/Onemofeit.A,SIGNATURE_TYPE_JAVAHSTR_EXT,0e 00 0e 00 08 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 32 33 2e 38 38 2e 31 31 33 2e 31 38 2f 4d 6f 6e 64 61 79 } //12 ://23.88.113.18/Monday
		$a_01_1 = {63 68 61 6d 61 33 32 2e 6a 70 65 67 } //2 chama32.jpeg
		$a_01_2 = {70 72 69 6e 63 69 70 61 6c 33 32 2e 6a 70 65 67 } //2 principal32.jpeg
		$a_01_3 = {70 67 2e 6a 70 65 67 } //2 pg.jpeg
		$a_01_4 = {63 68 61 6d 61 36 34 2e 6a 70 65 67 } //2 chama64.jpeg
		$a_01_5 = {70 72 69 6e 63 69 70 61 6c 36 34 2e 6a 70 65 67 } //2 principal64.jpeg
		$a_01_6 = {33 32 2e 6a 70 65 67 } //1 32.jpeg
		$a_01_7 = {36 34 2e 6a 70 65 67 } //1 64.jpeg
	condition:
		((#a_01_0  & 1)*12+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=14
 
}