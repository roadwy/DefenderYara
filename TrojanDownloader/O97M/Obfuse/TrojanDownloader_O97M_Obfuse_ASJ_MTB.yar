
rule TrojanDownloader_O97M_Obfuse_ASJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.ASJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 32 66 30 62 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 63 31 61 33 32 2c 20 46 61 6c 73 65 } //1 f2f0b.Open "GET", c1a32, False
		$a_01_1 = {62 39 38 62 39 20 3d 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 65 62 66 34 35 2e 22 20 26 20 66 31 32 33 37 } //1 b98b9 = "c:\programdata\ebf45." & f1237
		$a_01_2 = {61 62 39 62 61 20 66 64 64 61 39 28 30 29 20 2b 20 22 20 22 20 2b 20 62 39 38 62 39 28 22 68 65 6c 6c 6f 22 29 } //1 ab9ba fdda9(0) + " " + b98b9("hello")
		$a_01_3 = {2e 65 78 65 63 20 28 63 33 64 30 30 29 } //1 .exec (c3d00)
		$a_01_4 = {66 65 31 31 39 20 3d 20 53 70 6c 69 74 28 64 32 61 63 39 2c 20 63 34 63 63 39 29 } //1 fe119 = Split(d2ac9, c4cc9)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}