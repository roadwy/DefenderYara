
rule TrojanDownloader_O97M_Obfuse_BMK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BMK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 70 6c 69 74 28 90 02 09 2c 20 43 68 72 28 31 31 20 2b 20 31 31 20 2b 20 31 31 20 2b 20 31 31 29 29 90 00 } //1
		$a_03_1 = {53 68 65 6c 6c 20 90 02 09 20 26 20 22 20 22 20 26 90 00 } //1
		$a_01_2 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 } //1 = ActiveDocument.Content
		$a_01_3 = {3d 20 22 31 30 36 2c 31 31 39 2c 31 32 37 2c 39 39 2c 39 36 2c 31 32 35 2c 31 30 36 2c 31 32 35 22 } //1 = "106,119,127,99,96,125,106,125"
		$a_01_4 = {52 65 76 65 72 73 65 64 5f 53 74 72 69 6e 67 20 3d 20 52 65 76 65 72 73 65 64 5f 53 74 72 69 6e 67 20 26 20 4e 65 78 74 5f 43 68 61 72 } //1 Reversed_String = Reversed_String & Next_Char
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}