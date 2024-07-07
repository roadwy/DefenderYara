
rule TrojanDownloader_O97M_Dotraj_F{
	meta:
		description = "TrojanDownloader:O97M/Dotraj.F,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {20 3d 20 43 53 74 72 28 90 10 04 00 20 2b 20 41 74 6e 28 90 10 04 00 29 20 2d 20 90 1d 30 00 29 90 00 } //1
		$a_02_1 = {41 72 72 61 79 28 90 05 50 0b 61 2d 7a 41 2d 5a 30 2d 39 20 2c 20 53 68 65 6c 6c 28 90 05 50 0c 61 2d 7a 41 2d 5a 30 2d 39 20 2c 2b 29 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}