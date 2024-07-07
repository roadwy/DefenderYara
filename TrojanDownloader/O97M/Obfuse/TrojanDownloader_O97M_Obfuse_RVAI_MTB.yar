
rule TrojanDownloader_O97M_Obfuse_RVAI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVAI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 22 68 74 74 70 73 3a 2f 2f 72 6f 63 6b 74 72 61 64 65 2e 61 6c 70 68 61 63 6f 64 65 2e 6d 6f 62 69 2f 75 70 6c 6f 61 64 73 2f 62 69 6e 5f 50 72 6f 74 65 63 74 65 64 2e 65 78 65 22 2c 20 46 61 6c 73 65 } //1 .Open "get", "https://rocktrade.alphacode.mobi/uploads/bin_Protected.exe", False
		$a_01_1 = {2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 22 68 74 74 70 73 3a 2f 2f 63 72 31 6d 33 2e 77 6f 72 6b 2f 32 2f 4e 46 45 2d 30 31 30 39 32 30 2e 65 78 65 22 2c 20 46 61 6c 73 65 } //1 .Open "get", "https://cr1m3.work/2/NFE-010920.exe", False
		$a_01_2 = {53 65 74 20 66 73 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 Set fso = CreateObject("Scripting.FileSystemObject")
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 48 45 4c 4c 2e 41 50 50 4c 49 43 41 54 49 4f 4e 22 29 } //1 = CreateObject("SHELL.APPLICATION")
		$a_01_4 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}