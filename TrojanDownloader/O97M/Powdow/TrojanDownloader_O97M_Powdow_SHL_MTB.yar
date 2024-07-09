
rule TrojanDownloader_O97M_Powdow_SHL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SHL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 73 61 73 28 29 } //1 Private Function sas()
		$a_01_1 = {27 73 68 65 6c 6c 20 48 47 4a 48 47 } //1 'shell HGJHG
		$a_01_2 = {48 47 4a 48 47 20 3d 20 69 74 77 69 6c 6c 78 28 } //1 HGJHG = itwillx(
		$a_01_3 = {63 20 3d 20 41 73 63 28 4d 69 64 24 28 6a 6f 65 2c 20 69 2c 20 31 29 29 } //1 c = Asc(Mid$(joe, i, 1))
		$a_01_4 = {63 20 3d 20 63 20 2d 20 41 73 63 28 4d 69 64 24 28 78 77 2c 20 28 69 20 4d 6f 64 20 4c 65 6e 28 78 77 29 29 20 2b 20 31 2c 20 31 29 29 } //1 c = c - Asc(Mid$(xw, (i Mod Len(xw)) + 1, 1))
		$a_01_5 = {73 74 72 42 75 66 66 20 3d 20 73 74 72 42 75 66 66 20 26 20 43 68 72 28 63 20 41 6e 64 20 26 48 46 46 29 } //1 strBuff = strBuff & Chr(c And &HFF)
		$a_01_6 = {73 74 72 42 75 66 66 20 3d 20 6a 6f 65 } //1 strBuff = joe
		$a_03_7 = {22 4b 4b 22 29 90 0c 02 00 48 47 4a 48 47 20 3d 20 48 47 4a 48 47 20 2b 20 69 74 77 69 6c 6c 78 28 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1) >=8
 
}