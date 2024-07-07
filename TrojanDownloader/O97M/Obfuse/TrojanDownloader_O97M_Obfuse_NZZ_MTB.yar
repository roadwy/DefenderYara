
rule TrojanDownloader_O97M_Obfuse_NZZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.NZZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 72 69 76 61 74 65 20 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 42 65 66 6f 72 65 43 6c 6f 73 65 28 43 61 6e 63 65 6c 20 41 73 20 42 6f 6f 6c 65 61 6e 29 90 0c 02 00 53 68 65 6c 6c 26 20 5f 90 00 } //1
		$a_03_1 = {68 6f 6c 2e 70 6f 70 90 0c 02 00 45 6e 64 20 53 75 62 90 00 } //1
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 6c 6f 6c 28 29 20 41 73 20 53 74 72 69 6e 67 } //1 Function lol() As String
		$a_03_3 = {6c 6f 6c 20 3d 20 22 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 2e 6d 70 2f 6a 61 6f 73 64 6f 61 73 6b 64 61 6f 73 64 22 90 0c 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}