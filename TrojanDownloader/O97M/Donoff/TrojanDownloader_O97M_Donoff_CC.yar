
rule TrojanDownloader_O97M_Donoff_CC{
	meta:
		description = "TrojanDownloader:O97M/Donoff.CC,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3d 20 43 68 72 28 34 39 29 20 54 6f 20 4c 65 6e 28 90 02 20 29 90 02 20 3d 20 4d 69 64 28 90 02 20 2c 20 90 02 20 2c 20 43 68 72 28 34 39 29 29 90 02 20 3d 20 43 68 72 28 41 73 63 28 90 02 20 29 20 2d 20 90 02 20 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}