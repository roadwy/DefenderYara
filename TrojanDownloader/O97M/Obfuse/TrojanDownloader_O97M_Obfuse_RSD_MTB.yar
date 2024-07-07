
rule TrojanDownloader_O97M_Obfuse_RSD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.RSD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
		$a_03_1 = {43 61 6c 6c 20 90 02 08 2e 65 78 65 63 28 90 00 } //1
		$a_03_2 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 48 65 78 54 6f 53 74 72 69 6e 67 28 90 02 08 29 2c 20 46 61 6c 73 65 90 00 } //1
		$a_01_3 = {43 68 72 24 28 56 61 6c 28 22 26 48 22 20 26 20 4d 69 64 24 28 48 65 78 54 6f 53 74 72 2c 20 49 2c 20 32 29 29 29 } //1 Chr$(Val("&H" & Mid$(HexToStr, I, 2)))
		$a_01_4 = {46 75 6e 63 74 69 6f 6e 20 63 32 61 63 63 61 36 36 28 } //1 Function c2acca66(
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}