
rule TrojanDownloader_Linux_Bartallex_M{
	meta:
		description = "TrojanDownloader:Linux/Bartallex.M,SIGNATURE_TYPE_MACROHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 [0-04] 28 [0-04] 20 41 73 20 49 6e 74 65 67 65 72 29 0d 0a [0-04] 20 3d 20 43 68 72 28 [0-04] 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //10
		$a_01_1 = {26 20 22 6f 6d 2f 77 22 20 26 20 22 70 2d 69 6e 63 6c 75 64 65 73 2f 74 68 65 6d 65 2d 63 6f 6d 70 61 74 2f 22 } //1 & "om/w" & "p-includes/theme-compat/"
		$a_01_2 = {49 6e 74 28 } //1 Int(
		$a_01_3 = {28 41 54 54 48 20 2b 20 53 54 54 31 20 2b 20 4c 4e 53 53 29 } //1 (ATTH + STT1 + LNSS)
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}