
rule TrojanDownloader_O97M_Donoff_QB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 62 69 6e 22 20 26 20 22 2e 62 61 22 20 26 20 22 73 65 36 34 22 } //1 = "bin" & ".ba" & "se64"
		$a_01_1 = {45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 2e 41 64 6f 62 65 } //1 Environ("Temp") & "\.Adobe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_QB_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_03_1 = {47 65 74 46 69 6c 65 4f 6e 28 22 48 74 54 50 3a 2f 2f 61 66 67 63 6c 6f 75 64 37 2e 63 6f 6d 2f 75 70 6c 64 2f 90 02 10 2e 90 02 05 22 2c 20 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 22 90 02 10 2e 73 63 72 22 29 90 00 } //2
		$a_03_2 = {43 61 6c 6c 20 53 76 69 65 72 28 45 6e 76 69 72 6f 6e 28 22 61 70 70 64 61 74 61 22 29 20 26 20 22 90 02 10 2e 73 63 72 22 2c 20 76 62 48 69 64 65 29 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2) >=2
 
}