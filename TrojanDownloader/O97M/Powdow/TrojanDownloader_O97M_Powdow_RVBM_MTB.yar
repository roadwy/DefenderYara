
rule TrojanDownloader_O97M_Powdow_RVBM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 70 69 64 3d 73 68 65 6c 6c 28 22 63 6d 64 2f 63 63 65 72 74 75 74 69 6c 2e 65 78 65 2d 75 72 6c 63 61 63 68 65 2d 73 70 6c 69 74 2d 66 22 22 68 74 74 70 73 3a 2f 2f 66 61 72 6d 6c 61 72 67 65 62 61 72 73 2e 63 6f 2e 7a 61 2f 6d 61 78 2f [0-0f] 2e 65 78 65 22 22 [0-0f] 2e 65 78 65 2e 65 78 65 26 26 [0-0f] 2e 65 78 65 2e 65 78 65 22 2c 76 62 68 69 64 65 29 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Powdow_RVBM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVBM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {79 38 39 68 67 6a 30 30 2e 61 41 7a 5a 46 28 29 2e 45 78 65 63 28 71 69 62 4b 28 29 20 2b 20 22 20 22 20 2b 20 54 70 62 73 64 28 29 29 } //1 y89hgj00.aAzZF().Exec(qibK() + " " + Tpbsd())
		$a_01_1 = {22 70 22 20 2b 20 61 49 72 46 36 20 2b 20 22 68 65 6c 6c 22 } //1 "p" + aIrF6 + "hell"
		$a_01_2 = {22 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 22 20 2b 20 61 49 72 46 35 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_3 = {41 63 74 69 76 65 53 68 65 65 74 2e 53 68 61 70 65 73 28 31 29 2e 54 65 78 74 46 72 61 6d 65 2e 43 68 61 72 61 63 74 65 72 73 2e 54 65 78 74 } //1 ActiveSheet.Shapes(1).TextFrame.Characters.Text
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}