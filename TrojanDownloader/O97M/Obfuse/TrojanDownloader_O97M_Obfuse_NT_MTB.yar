
rule TrojanDownloader_O97M_Obfuse_NT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 [0-20] 20 26 20 22 5c [0-20] 2e 78 73 22 20 26 20 [0-20] 28 29 2c 20 31 2c 20 31 29 } //1
		$a_01_1 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 } //1 = Chr("&h" & Mid(
		$a_01_2 = {22 74 6d 70 22 } //1 "tmp"
		$a_01_3 = {3d 20 22 22 } //1 = ""
		$a_01_4 = {2e 54 65 78 74 } //1 .Text
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}