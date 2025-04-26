
rule TrojanDownloader_O97M_Obfuse_IO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.IO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 65 78 65 2e [0-07] 2f 73 63 6f 64 74 68 2f 70 6d 61 78 2f 72 6d 2f 70 6d 61 78 2f 67 72 6f 2e 73 6e 64 6b 63 75 64 2e 72 65 76 72 65 73 73 6e 69 6c 6c 6f 63 2f 2f 3a 70 74 74 68 22 } //1
		$a_03_1 = {26 20 22 5c 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 2e [0-07] 22 29 } //1
		$a_01_2 = {2e 52 75 6e 20 70 20 26 20 22 20 22 20 26 20 6a 20 26 20 22 20 22 2c } //1 .Run p & " " & j & " ",
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}