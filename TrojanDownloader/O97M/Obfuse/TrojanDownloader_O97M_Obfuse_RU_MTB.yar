
rule TrojanDownloader_O97M_Obfuse_RU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 6f 57 6e 6c 6f 41 64 73 54 72 49 6e 47 } //1 DoWnloAdsTrInG
		$a_03_1 = {70 61 73 74 65 2e 65 65 2f 72 2f 76 35 65 38 45 90 0a 1b 00 68 74 27 2b 27 74 70 3a 2f 2f } //1
		$a_00_2 = {4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 } //1 Net.WebClient
		$a_00_3 = {77 65 72 73 68 65 6c 6c 20 2d 43 6f 6d 6d 61 6e 64 } //1 wershell -Command
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_RU_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {3d 20 49 73 4e 75 6d 65 72 69 63 28 22 22 29 } //1 = IsNumeric("")
		$a_03_1 = {2e 49 74 65 6d 28 29 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 [0-15] 2c } //1
		$a_03_2 = {22 26 48 22 [0-06] 26 20 4d 69 64 24 } //1
		$a_03_3 = {3d 20 52 65 70 6c 61 63 65 28 22 [0-20] 26 48 [0-20] 22 2c } //1
		$a_03_4 = {3d 20 52 65 70 6c 61 63 65 28 [0-18] 2c 20 [0-20] 2c 20 22 22 29 } //1
		$a_01_5 = {26 20 22 34 } //1 & "4
		$a_01_6 = {26 20 22 33 } //1 & "3
		$a_01_7 = {26 20 22 32 } //1 & "2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}