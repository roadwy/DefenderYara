
rule TrojanDownloader_O97M_Obfuse_PF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_00_1 = {53 68 65 6c 6c 20 28 76 61 72 29 } //1 Shell (var)
		$a_02_2 = {2e 73 73 6c 62 6c 69 6e 64 61 64 6f 2e 63 6f 6d 2f 90 0a 3c 00 3d 20 22 6d 73 68 54 41 20 90 03 04 05 68 74 74 70 68 74 74 70 73 3a 2f 2f 74 72 61 6e 73 76 61 6c 65 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_PF_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {26 20 43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 90 02 20 2c 20 90 02 20 2c 20 32 29 29 29 90 00 } //1
		$a_03_1 = {3d 20 31 20 54 6f 20 4c 65 6e 28 90 02 25 29 20 53 74 65 70 20 90 00 } //1
		$a_01_2 = {26 20 22 34 62 } //1 & "4b
		$a_01_3 = {26 20 22 35 } //1 & "5
		$a_01_4 = {26 20 22 37 } //1 & "7
		$a_01_5 = {33 33 33 34 33 33 } //1 333433
		$a_01_6 = {3d 20 49 73 4e 75 6c 6c 28 22 22 29 } //1 = IsNull("")
		$a_01_7 = {3d 20 22 31 4e 6f 72 6d 61 6c 2e 54 68 69 73 44 6f 63 75 6d 65 6e 74 22 } //1 = "1Normal.ThisDocument"
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}