
rule TrojanDownloader_O97M_Obfusmacro_ARA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfusmacro.ARA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 20 22 77 69 6e 6d 67 6d 74 73 3a 57 69 22 20 2b 90 02 14 2b 20 22 6e 33 32 5f 50 72 6f 63 65 73 73 73 74 61 72 74 75 70 22 20 2b 90 00 } //10
		$a_03_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 14 2e 43 72 65 61 74 65 90 02 96 2b 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 90 00 } //10
		$a_03_2 = {2b 20 22 77 69 6e 6d 67 6d 74 73 3a 57 69 22 20 2b 90 02 14 2b 20 22 6e 33 32 5f 50 72 6f 63 65 73 73 22 20 2b 90 00 } //10
		$a_01_3 = {53 68 6f 77 57 69 6e 64 6f 77 20 3d } //1 ShowWindow =
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_01_3  & 1)*1) >=21
 
}