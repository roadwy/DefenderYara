
rule TrojanDownloader_O97M_Obfuse_RVAX_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RVAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4f 62 6a 65 63 74 28 52 61 6e 67 65 28 22 41 31 30 36 22 29 2e 56 61 6c 75 65 29 } //1 GetObject(Range("A106").Value)
		$a_01_1 = {52 61 6e 67 65 28 22 41 31 30 33 22 29 2e 56 61 6c 75 65 20 2b 20 22 20 2d 22 20 2b 20 52 61 6e 67 65 28 22 41 31 30 30 22 29 2e 56 61 6c 75 65 } //1 Range("A103").Value + " -" + Range("A100").Value
		$a_03_2 = {2e 4f 70 65 6e 28 76 30 64 66 20 2b 20 22 5c [0-0a] 2e 62 61 74 22 29 } //1
		$a_01_3 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 } //1 = Environ("AppData")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}