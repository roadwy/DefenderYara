
rule TrojanDownloader_O97M_Obfuse_RVAK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVAK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 6e 74 20 23 31 2c 20 52 65 70 6c 61 63 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 2c 20 22 26 6c 74 3b 22 2c 20 22 22 29 } //1 Print #1, Replace(ActiveDocument.Range.Text, "&lt;", "")
		$a_03_1 = {45 78 63 65 6c 20 68 6f 70 ?? ?? ?? ?? 20 26 20 22 2e 2e 2e 68 54 61 22 } //1
		$a_03_2 = {4e 65 77 20 57 73 68 53 68 65 6c 6c 0d 0a 65 78 63 65 6c [0-0a] 2e 72 75 6e 20 72 61 70 [0-0a] 0d 0a 45 6e 64 20 53 75 62 } //1
		$a_03_3 = {53 75 62 20 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 0d 0a 43 61 6c 6c 20 73 28 22 [0-14] 22 29 0d 0a 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}