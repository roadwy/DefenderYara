
rule TrojanDownloader_O97M_Obfuse_PKJA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PKJA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 62 76 2e [0-05] 2f 63 65 73 2f 74 65 6e 2e 73 6e 64 2d 63 69 6d 61 6e 79 64 2e 6f 67 6e 6f 6d 70 75 78 2f 2f 3a } //1
		$a_03_1 = {73 74 61 72 74 2d 70 72 6f 63 65 73 73 28 24 65 6e 76 3a 74 65 6d 70 2b 20 27 5c [0-0a] 2e 76 62 73 } //1
		$a_01_2 = {45 72 72 6f 72 41 63 74 69 6f 6e 50 72 65 66 65 72 65 6e 63 65 20 3d 20 27 53 69 6c 65 6e 74 6c 79 43 6f 6e 74 69 6e 75 65 } //1 ErrorActionPreference = 'SilentlyContinue
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}