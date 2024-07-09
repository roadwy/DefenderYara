
rule TrojanDownloader_O97M_Donoff_MTZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MTZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_03_0 = {66 20 3d 20 78 73 61 64 77 71 64 77 71 64 28 [0-0f] 29 } //2
		$a_01_1 = {53 68 65 6c 6c 20 66 } //2 Shell f
		$a_01_2 = {78 73 61 64 77 71 64 77 71 64 20 3d 20 73 74 72 49 6e 70 75 74 } //2 xsadwqdwqd = strInput
		$a_01_3 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //2 Workbook_Open()
		$a_01_4 = {73 61 64 73 61 64 } //2 sadsad
		$a_01_5 = {4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 69 2c 20 31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 69 2c 20 31 29 29 20 2d 20 6e 29 } //2 Mid(strInput, i, 1) = Chr(Asc(Mid(strInput, i, 1)) - n)
		$a_01_6 = {64 50 44 51 6e 41 62 5a 50 52 47 69 53 61 58 20 3d 20 64 50 44 51 6e 41 62 5a 50 52 47 69 53 61 58 20 2b 20 22 70 22 } //2 dPDQnAbZPRGiSaX = dPDQnAbZPRGiSaX + "p"
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}