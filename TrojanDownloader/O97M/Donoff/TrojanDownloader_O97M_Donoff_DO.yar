
rule TrojanDownloader_O97M_Donoff_DO{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DO,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 62 6c 65 53 74 79 6c 65 20 3d 20 22 22 0d 0a 90 02 0a 20 3d 20 90 02 0a 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //1
		$a_03_1 = {53 75 62 20 90 02 0a 28 29 0d 0a 0d 0a 49 66 20 90 02 0a 20 54 68 65 6e 0d 0a 53 68 65 6c 6c 20 90 02 0a 2c 20 90 02 06 0d 0a 45 6e 64 20 49 66 0d 0a 45 6e 64 20 53 75 62 0d 0a 53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}