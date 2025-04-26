
rule TrojanDownloader_O97M_Obfuse_PBI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PBI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 22 6d 73 68 74 61 2e 65 78 65 20 6a 61 76 61 73 63 72 69 70 74 3a [0-06] 3d 28 47 65 74 4f 62 6a 65 63 74 28 22 22 73 63 72 69 70 74 3a 68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 53 74 65 41 6d 65 52 2f 6d 61 6c 77 65 72 6a 6f 62 73 2f 6d 61 73 74 65 72 2f 73 63 72 69 70 74 6c 65 74 22 22 29 29 2e 45 78 65 63 28 29 3b 63 6c 6f 73 65 28 29 3b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}