
rule TrojanDownloader_O97M_Obfuse_PRW_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PRW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 69 61 6a 69 77 6e 22 } //1 "https://www.bitly.com/asiajiwn"
		$a_01_1 = {22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 } //1 "m" + "s" + "h" + "t" + "a"
		$a_03_2 = {47 65 74 4f 62 6a 65 63 74 20 5f 90 0c 02 00 28 53 74 72 52 65 76 65 72 73 65 20 5f 90 0c 02 00 28 22 30 30 30 30 34 35 33 35 35 34 34 34 2d 45 39 34 41 2d 45 43 31 31 2d 39 37 32 43 2d 30 32 36 39 30 37 33 31 3a 77 65 6e 22 29 20 5f 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}