
rule TrojanDownloader_O97M_EncDoc_PAB_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 22 0d 0a 44 6c 6c 4d 61 69 6e 28 69 29 2e 52 75 6e 50 45 20 3d 20 22 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 68 6a 64 6b 71 6f 77 64 68 71 6f 77 64 68 22 } //1
		$a_01_1 = {28 41 73 73 20 2b 20 41 73 73 32 20 2b 20 41 73 73 33 20 2b 20 41 73 73 34 29 } //1 (Ass + Ass2 + Ass3 + Ass4)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}