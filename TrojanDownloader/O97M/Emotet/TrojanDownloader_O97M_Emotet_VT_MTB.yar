
rule TrojanDownloader_O97M_Emotet_VT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 20 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 90 02 20 2c 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //1
		$a_03_1 = {2b 20 43 68 72 57 28 90 02 20 2e 5a 6f 6f 6d 20 2b 20 90 02 08 29 20 2b 20 22 90 02 40 77 90 02 30 69 90 02 30 6e 90 02 30 33 90 02 30 32 90 02 45 22 20 2b 90 00 } //1
		$a_01_2 = {43 68 72 57 28 49 6e 74 28 77 64 4b 65 79 50 29 29 } //1 ChrW(Int(wdKeyP))
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}