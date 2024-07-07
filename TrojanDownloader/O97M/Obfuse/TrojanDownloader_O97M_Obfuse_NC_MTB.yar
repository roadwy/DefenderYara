
rule TrojanDownloader_O97M_Obfuse_NC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 14 2e 43 6f 6e 74 72 6f 6c 73 28 31 29 2e 56 61 6c 75 65 2c 20 54 72 75 65 29 90 00 } //1
		$a_03_1 = {2e 57 72 69 74 65 4c 69 6e 65 20 28 90 02 14 2e 43 6f 6e 74 72 6f 6c 73 28 30 29 2e 43 61 70 74 69 6f 6e 29 90 00 } //1
		$a_03_2 = {2e 4f 70 65 6e 20 90 02 25 2e 56 61 6c 75 65 90 00 } //1
		$a_01_3 = {2e 43 6c 6f 73 65 } //1 .Close
		$a_01_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_5 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}