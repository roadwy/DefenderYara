
rule TrojanDownloader_O97M_EncDoc_PDC_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 4c 6e 67 28 73 61 28 22 6a 22 2c 20 22 48 6b 45 62 78 6c 67 45 77 22 29 29 } //1 = CLng(sa("j", "HkEbxlgEw"))
		$a_01_1 = {3d 20 53 74 72 43 6f 6e 76 28 52 28 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 } //1 = StrConv(R(), vbUnicode)
		$a_03_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 61 28 22 [0-1f] 22 2c 20 22 67 6e 34 63 52 4b 45 42 70 22 29 20 2b 20 73 61 28 22 [0-1f] 22 2c 20 22 6e 49 59 58 46 45 51 42 66 22 29 20 2b 20 73 61 28 22 [0-1f] 22 2c 20 22 71 30 71 34 44 51 38 74 5a 22 29 20 2b } //1
		$a_01_3 = {53 68 65 6c 6c 2e 52 75 6e 20 73 61 73 61 2c 20 53 74 79 6c 65 } //1 Shell.Run sasa, Style
		$a_01_4 = {73 61 73 61 20 3d 20 78 30 72 20 26 20 68 30 79 20 26 20 47 47 49 5a 49 } //1 sasa = x0r & h0y & GGIZI
		$a_03_5 = {3d 20 52 65 70 6c 61 63 65 28 78 30 61 2c 20 73 61 28 22 [0-1f] 22 29 2c 20 73 61 28 22 [0-1f] 22 29 29 3a 20 78 66 66 20 3d 20 52 65 70 6c 61 63 65 28 78 30 64 2c 20 73 61 28 22 [0-1f] 22 29 2c 20 73 61 28 22 [0-1f] 22 29 29 3a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}