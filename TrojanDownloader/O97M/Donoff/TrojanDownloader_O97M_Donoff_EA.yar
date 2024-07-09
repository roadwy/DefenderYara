
rule TrojanDownloader_O97M_Donoff_EA{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EA,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {3d 20 45 6e 76 69 72 6f 6e 28 [0-0f] 29 20 26 } //1
		$a_02_1 = {3d 20 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 28 30 2c 20 [0-0f] 2c 20 [0-0f] 2c 20 30 2c 20 30 29 } //1
		$a_02_2 = {3d 20 41 72 72 61 79 28 57 69 6e 45 78 65 63 28 [0-0f] 20 26 20 [0-0f] 2c 20 46 61 6c 73 65 29 29 28 30 29 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}