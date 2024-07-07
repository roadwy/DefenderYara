
rule TrojanDownloader_O97M_Obfuse_IG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 70 3a 2f 2f 31 39 32 2e 39 39 2e 32 31 34 2e 33 32 2f 77 6f 72 64 31 2e 74 6d 70 22 } //1 = "http://192.99.214.32/word1.tmp"
		$a_01_1 = {43 61 6c 6c 20 53 68 65 6c 6c 28 } //1 Call Shell(
		$a_03_2 = {22 43 3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 90 02 05 2e 65 72 74 22 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}