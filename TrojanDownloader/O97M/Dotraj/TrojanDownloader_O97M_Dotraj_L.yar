
rule TrojanDownloader_O97M_Dotraj_L{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.L,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_02_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 [0-10] 0d 0a 45 6e 64 20 53 75 62 [0-90] 20 46 6f 72 20 45 61 63 68 20 [0-03] 20 49 6e 20 [0-30] 49 66 20 4c 65 6e 28 [0-30] 20 3d 20 90 1b 00 20 2b 20 43 68 72 28 [0-03] 20 2d 20 90 10 03 00 29 90 0e 10 00 45 6e 64 20 49 66 } //3
	condition:
		((#a_02_0  & 1)*3) >=3
 
}