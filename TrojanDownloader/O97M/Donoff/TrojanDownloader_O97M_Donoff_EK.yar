
rule TrojanDownloader_O97M_Donoff_EK{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EK,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 [0-10] 2c 20 73 28 [0-03] 2c 20 22 90 17 03 04 04 04 65 70 4f 6e 6e 65 70 4f 70 4f 6e 65 22 2c 20 [0-03] 29 2c 20 31 2c 20 73 28 [0-03] 2c 20 22 45 47 54 22 2c 20 [0-03] 29 2c 20 73 28 } //1
		$a_03_1 = {28 41 72 72 61 79 28 73 28 [0-03] 2c 20 22 90 17 03 06 06 06 4d 41 4e 4f 5a 41 4e 4f 5a 41 4d 41 41 4d 41 4e 4f 5a 22 2c 20 [0-03] 29 2c 20 73 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}