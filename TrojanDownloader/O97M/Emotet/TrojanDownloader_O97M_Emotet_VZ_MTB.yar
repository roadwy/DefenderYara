
rule TrojanDownloader_O97M_Emotet_VZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 [0-20] 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 [0-20] 20 2b 20 [0-20] 20 2b 20 [0-20] 20 2b 20 [0-10] 2c 20 [0-20] 2c 20 [0-20] 29 } //1
		$a_03_1 = {3d 20 52 65 70 6c 61 63 65 ?? 28 22 [0-35] 2c 20 [0-20] 2c 20 [0-20] 29 } //1
		$a_03_2 = {3d 20 49 6e 53 74 72 52 65 76 28 22 [0-35] 2c 20 [0-20] 29 } //1
		$a_03_3 = {73 68 6f 77 77 69 6e 64 6f 77 20 3d 20 [0-20] 20 2b } //1
		$a_01_4 = {3d 20 22 22 } //1 = ""
		$a_01_5 = {2e 50 61 67 65 73 28 30 29 2e 43 61 70 74 69 6f 6e } //1 .Pages(0).Caption
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Emotet_VZ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 [0-25] 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 [0-25] 2e [0-30] 20 2b 20 [0-25] 20 2b 20 [0-25] 2c } //1
		$a_03_1 = {43 61 6c 6c 20 [0-20] 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 4e 6f 4c 69 6e 65 42 72 65 61 6b 41 66 74 65 72 20 2b 20 [0-20] 20 2b 20 [0-10] 2c 20 [0-20] 2c 20 [0-15] 29 } //1
		$a_03_2 = {2b 20 43 68 72 57 28 [0-25] 2e 5a 6f 6f 6d [0-20] 29 20 2b 20 22 [0-40] 77 [0-40] 69 [0-40] 6e [0-40] 33 [0-40] 32 [0-40] 22 20 2b } //1
		$a_03_3 = {2b 20 43 68 72 57 28 [0-25] 2e 5a 6f 6f 6d [0-20] 29 20 2b 20 [0-20] 2e [0-20] 2e 54 61 67 20 2b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}