
rule TrojanDownloader_O97M_Obfuse_CV{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.CV,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 77 28 [0-10] 29 } //1
		$a_01_1 = {3d 20 22 53 48 45 22 20 26 20 22 4c 4c 20 22 } //10 = "SHE" & "LL "
		$a_03_2 = {43 61 6c 6c 20 [0-10] 28 [0-10] 20 26 } //1
		$a_01_3 = {3d 20 22 6f 77 22 } //1 = "ow"
		$a_03_4 = {44 69 6d 20 [0-10] 28 90 10 03 00 20 54 6f 20 90 10 03 00 29 20 41 73 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*10+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=13
 
}