
rule TrojanDownloader_O97M_Valak_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Valak.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 6d 61 69 6e 2e 74 68 65 6d 65 22 } //2  = Environ("temp") & "\main.theme"
		$a_03_1 = {20 3d 20 53 74 72 43 6f 6e 76 28 ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 36 34 29 } //1
		$a_03_2 = {53 65 74 20 90 05 08 06 61 2d 7a 30 2d 39 20 3d 20 4e 65 77 20 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 36 30 } //1
		$a_03_3 = {43 61 6c 6c 20 90 05 08 06 61 2d 7a 30 2d 39 2e 4f 70 65 6e 28 22 47 45 54 22 2c 20 90 05 08 06 61 2d 7a 30 2d 39 2c 20 46 61 6c 73 65 29 } //1
		$a_03_4 = {53 65 74 20 90 05 08 06 61 2d 7a 30 2d 39 20 3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1
		$a_03_5 = {53 65 74 20 90 05 08 06 61 2d 7a 30 2d 39 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}