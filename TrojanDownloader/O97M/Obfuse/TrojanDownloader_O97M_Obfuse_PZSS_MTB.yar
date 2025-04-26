
rule TrojanDownloader_O97M_Obfuse_PZSS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PZSS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 6d 61 71 61 72 61 61 79 68 6d 77 65 6f 72 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 6e 78 79 6f 6c 78 6d 63 69 29 } //1 Set maqaraayhmweor = CreateObject(nxyolxmci)
		$a_01_1 = {3d 20 6d 61 71 61 72 61 61 79 68 6d 77 65 6f 72 2e 52 75 6e 28 70 6a 65 68 79 65 76 7a 71 67 79 6c 70 6a 2c 20 72 79 65 76 74 64 64 66 29 } //1 = maqaraayhmweor.Run(pjehyevzqgylpj, ryevtddf)
		$a_01_2 = {3d 20 22 76 64 62 67 64 20 67 66 64 62 20 66 73 76 76 20 2b 20 76 66 64 65 72 20 22 } //1 = "vdbgd gfdb fsvv + vfder "
		$a_01_3 = {3d 20 43 68 72 28 66 72 5f 5f 5f 65 65 20 2d 20 36 39 29 } //1 = Chr(fr___ee - 69)
		$a_01_4 = {3d 20 22 65 72 74 65 62 20 74 72 75 74 6a 20 68 79 74 79 72 22 } //1 = "erteb trutj hytyr"
		$a_01_5 = {43 61 6c 6c 20 6a 64 71 77 70 2e 63 6a 6b 67 6a 6f 6d 6e 73 71 70 75 62 75 77 76 6b 65 66 75 } //1 Call jdqwp.cjkgjomnsqpubuwvkefu
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}