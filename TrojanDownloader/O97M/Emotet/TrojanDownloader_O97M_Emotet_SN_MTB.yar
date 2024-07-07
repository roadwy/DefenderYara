
rule TrojanDownloader_O97M_Emotet_SN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 43 72 65 61 74 65 } //1 .Create
		$a_01_1 = {2b 20 28 22 53 54 41 52 54 55 22 29 } //1 + ("STARTU")
		$a_03_2 = {22 77 69 6e 90 02 06 6d 90 02 06 67 90 02 06 6d 90 02 06 74 90 02 06 73 90 02 06 3a 90 02 06 57 90 02 06 69 90 02 06 6e 90 02 06 33 90 02 06 32 90 02 06 5f 90 00 } //1
		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}