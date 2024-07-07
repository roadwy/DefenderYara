
rule TrojanDownloader_O97M_Obfuse_PAR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PAR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 50 20 2d 73 74 61 20 2d 77 20 31 20 2d 65 6e 63 20 20 55 77 42 46 41 48 51 41 4c 51 42 57 41 47 45 41 55 67 } //1 powershell -noP -sta -w 1 -enc  UwBFAHQALQBWAGEAUg
		$a_03_1 = {53 65 74 20 90 02 08 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 90 00 } //1
		$a_03_2 = {2e 52 75 6e 20 28 90 02 06 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}