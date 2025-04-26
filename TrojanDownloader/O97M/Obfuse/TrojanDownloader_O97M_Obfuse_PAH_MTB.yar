
rule TrojanDownloader_O97M_Obfuse_PAH_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_03_1 = {65 78 65 63 20 3d 20 [0-06] 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 [0-06] 49 45 58 20 [0-04] 6e 65 77 2d 6f 62 6a 65 63 74 20 6e 65 74 2e 77 65 62 63 6c 69 65 6e 74 [0-04] 2e 64 6f 77 6e 6c 6f 61 64 73 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f [0-04] 2e [0-04] 2e [0-04] 2e [0-04] 2f 70 61 79 6c 6f 61 64 2e 74 78 74 20 27 [0-04] 22 22 22 } //1
		$a_01_2 = {53 68 65 6c 6c 20 28 65 78 65 63 29 } //1 Shell (exec)
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}