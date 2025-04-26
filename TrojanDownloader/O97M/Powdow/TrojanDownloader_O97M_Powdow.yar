
rule TrojanDownloader_O97M_Powdow{
	meta:
		description = "TrojanDownloader:O97M/Powdow,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 53 74 72 43 6f 6e 76 28 [0-0f] 2c 20 76 62 55 6e 69 63 6f 64 65 29 29 } //1
		$a_01_1 = {53 68 65 6c 6c 20 28 52 65 70 6c 61 63 65 28 52 65 70 6c 61 63 65 28 53 70 6c 69 74 28 } //1 Shell (Replace(Replace(Split(
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}