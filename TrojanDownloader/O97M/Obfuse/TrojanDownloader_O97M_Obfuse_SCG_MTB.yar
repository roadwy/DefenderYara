
rule TrojanDownloader_O97M_Obfuse_SCG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SCG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 6b 69 2c 20 67 61 73 2c 20 31 29 29 20 2d 20 62 62 29 } //1 = Chr(Asc(Mid(ki, gas, 1)) - bb)
		$a_03_1 = {53 68 65 6c 6c 20 52 65 70 6c 61 63 65 28 73 73 28 22 73 72 [0-2d] 76 6b 68 6f 6f 31 68 7b } //1
		$a_01_2 = {2c 22 29 2c 20 22 20 53 41 4f 46 53 4f 41 46 53 41 46 53 41 46 20 22 2c 20 22 22 29 } //1 ,"), " SAOFSOAFSAFSAF ", "")
		$a_01_3 = {73 73 20 3d 20 6b 69 } //1 ss = ki
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}