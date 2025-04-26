
rule TrojanDownloader_O97M_MudWat_A{
	meta:
		description = "TrojanDownloader:O97M/MudWat.A,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 22 29 90 0e 10 00 [0-10] 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 [0-20] 2e 4f 70 65 6e 20 22 47 45 54 22 2c [0-60] 26 20 90 1b 01 2c 20 46 61 6c 73 65 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}