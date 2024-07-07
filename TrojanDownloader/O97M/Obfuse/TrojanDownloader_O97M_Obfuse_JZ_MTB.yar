
rule TrojanDownloader_O97M_Obfuse_JZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.JZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 5c 54 65 6d 70 5c 90 02 15 20 26 20 22 2e 6a 22 20 26 20 22 73 22 90 00 } //1
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 64 29 } //1 = Environ(d)
		$a_03_2 = {4f 70 65 6e 20 90 02 15 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 90 00 } //1
		$a_01_3 = {2e 43 61 70 74 69 6f 6e } //1 .Caption
		$a_01_4 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 = CreateObject("Shell.Application")
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}