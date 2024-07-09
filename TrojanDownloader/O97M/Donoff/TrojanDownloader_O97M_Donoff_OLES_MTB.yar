
rule TrojanDownloader_O97M_Donoff_OLES_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.OLES!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 6e 31 2c 20 41 32 2c 20 22 22 2c 20 22 22 2c 20 30 } //1 .ShellExecute "P" + n1, A2, "", "", 0
		$a_03_1 = {3d 20 4c 4f 4c 2e [0-20] 28 [0-20] 28 [0-20] 29 2c 20 74 38 68 67 30 2c 20 79 37 30 66 64 73 64 29 } //1
		$a_01_2 = {2e 52 61 6e 67 65 28 22 44 35 30 30 22 29 2e 4e 6f 74 65 54 65 78 74 20 2b } //1 .Range("D500").NoteText +
		$a_01_3 = {2e 52 61 6e 67 65 28 22 44 35 30 37 22 29 2e 4e 6f 74 65 54 65 78 74 } //1 .Range("D507").NoteText
		$a_01_4 = {57 6f 72 6b 73 68 65 65 74 73 28 22 53 68 65 65 74 31 22 29 } //1 Worksheets("Sheet1")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}