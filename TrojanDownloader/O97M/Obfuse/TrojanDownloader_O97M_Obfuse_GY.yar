
rule TrojanDownloader_O97M_Obfuse_GY{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.GY,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {53 65 74 20 90 02 05 20 3d 20 90 02 06 2e 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 90 00 } //1
		$a_03_1 = {3d 20 52 69 67 68 74 28 90 02 08 2c 20 4c 65 6e 28 90 02 08 29 20 2d 20 31 29 90 00 } //1
		$a_01_2 = {43 68 72 28 39 32 29 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 65 22 } //1 Chr(92) & Rnd & ".jse"
		$a_01_3 = {53 65 74 20 57 73 68 53 63 72 69 70 74 20 3d 20 6f 62 6a 4f 4c 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Set WshScript = objOL.CreateObject("Shell.Application")
		$a_01_4 = {57 73 68 53 63 72 69 70 74 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 WshScript.ShellExecute
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}