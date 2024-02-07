
rule TrojanDownloader_O97M_EncDoc_QVSM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.QVSM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 71 77 41 4c 6f 75 52 2e 59 6b 6d } //01 00  JqwALouR.Ykm
		$a_01_1 = {3d 20 4d 69 64 28 73 2c 20 70 6f 73 20 2b 20 31 2c 20 31 29 } //01 00  = Mid(s, pos + 1, 1)
		$a_01_2 = {3d 20 4d 69 64 28 78 2c 20 79 20 2b 20 31 2c 20 31 29 } //00 00  = Mid(x, y + 1, 1)
	condition:
		any of ($a_*)
 
}