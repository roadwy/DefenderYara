
rule TrojanDownloader_O97M_Sheurnif_A{
	meta:
		description = "TrojanDownloader:O97M/Sheurnif.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 6c 65 65 70 20 3d 20 22 62 69 74 73 61 64 6d 69 6e 20 2f 74 72 61 6e 73 66 65 72 } //1 sleep = "bitsadmin /transfer
		$a_00_1 = {2f 64 6f 77 6e 6c 6f 61 64 20 2f 70 72 69 6f 72 69 74 79 20 68 69 67 68 20 68 74 74 70 3a 2f 2f } //1 /download /priority high http://
		$a_00_2 = {66 6f 72 66 69 6c 65 73 20 2f 53 20 2f 4d 20 2a 2e 64 6f 63 20 2f 43 20 22 22 63 6d 64 20 2f 63 20 64 65 6c 20 40 66 69 6c 65 22 22 22 } //1 forfiles /S /M *.doc /C ""cmd /c del @file"""
		$a_00_3 = {3d 20 49 6e 74 28 28 39 39 39 39 39 39 39 20 2a 20 52 6e 64 29 20 2b 20 31 29 } //1 = Int((9999999 * Rnd) + 1)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}