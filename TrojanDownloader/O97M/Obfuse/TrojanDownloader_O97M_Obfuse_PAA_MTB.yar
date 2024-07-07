
rule TrojanDownloader_O97M_Obfuse_PAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 42 5f 4e 61 6d 65 20 3d 20 22 76 61 72 46 75 6e 63 50 74 72 22 } //1 VB_Name = "varFuncPtr"
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 74 6f 72 61 67 65 41 72 67 4c 69 62 28 22 6c 6c 65 68 73 2e 74 70 69 72 63 73 77 22 29 29 2e } //1 CreateObject(storageArgLib("llehs.tpircsw")).
		$a_01_2 = {3d 20 4d 69 64 28 6c 6f 61 64 4c 69 73 74 62 6f 78 2c 20 6d 65 6d 54 65 78 74 62 6f 78 2c 20 31 30 30 30 30 30 30 29 } //1 = Mid(loadListbox, memTextbox, 1000000)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Obfuse_PAA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {45 58 45 43 28 22 63 6d 64 20 2f 63 20 70 6f 90 02 02 77 65 72 90 02 02 73 68 65 6c 6c 20 2d 77 20 31 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 90 02 02 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 33 70 73 61 71 6d 6d 27 2c 28 24 65 6e 76 3a 61 70 70 64 61 74 61 20 2b 20 27 5c 90 02 10 2e 65 78 65 27 29 29 22 29 90 00 } //1
		$a_02_1 = {45 58 45 43 28 22 63 6d 64 20 2f 63 20 70 6f 90 02 02 77 65 72 90 02 02 73 68 65 6c 6c 20 2d 77 20 31 20 53 74 61 72 74 2d 53 6c 65 65 70 20 90 02 04 3b 20 73 54 41 72 74 2d 90 02 06 6f 63 65 73 73 20 24 65 6e 76 3a 61 70 70 64 61 74 61 5c 90 02 10 2e 65 78 65 22 29 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}