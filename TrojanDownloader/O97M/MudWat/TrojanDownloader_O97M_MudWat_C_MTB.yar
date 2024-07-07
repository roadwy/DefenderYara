
rule TrojanDownloader_O97M_MudWat_C_MTB{
	meta:
		description = "TrojanDownloader:O97M/MudWat.C!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {56 62 4d 65 74 68 6f 64 2c 20 90 02 15 2c 20 45 6e 76 69 72 6f 6e 28 90 02 15 29 20 26 90 00 } //1
		$a_01_1 = {54 65 78 74 20 26 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 4e 61 6d 65 } //1 Text & ThisWorkbook.Name
		$a_01_2 = {3d 20 22 22 } //1 = ""
		$a_01_3 = {3d 20 41 73 63 28 4d 69 64 28 71 2c 20 28 6f 20 4d 6f 64 20 4c 65 6e 28 } //1 = Asc(Mid(q, (o Mod Len(
		$a_01_4 = {22 54 68 65 20 76 65 72 73 69 6f 6e 20 6f 66 20 45 78 63 65 6c 20 66 6f 72 20 57 69 6e 64 6f 77 73 20 79 6f 75 20 61 72 65 20 75 73 69 6e 67 20 69 73 20 6e 6f 74 20 63 6f 6d 70 61 74 69 62 6c 65 20 77 69 74 68 20 74 68 69 73 20 64 6f 63 75 6d 65 6e 74 22 2c 20 5f } //1 "The version of Excel for Windows you are using is not compatible with this document", _
		$a_01_5 = {43 6c 6f 73 65 20 23 31 } //1 Close #1
		$a_03_6 = {4f 70 65 6e 20 45 6e 76 69 72 6f 6e 28 90 02 15 29 20 26 20 90 02 15 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}