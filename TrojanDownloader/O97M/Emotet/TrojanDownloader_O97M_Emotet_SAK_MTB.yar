
rule TrojanDownloader_O97M_Emotet_SAK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SAK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 3d 20 22 77 5d 78 6d 5b 76 72 6f 77 5d 78 6d 5b 76 77 5d 78 6d 5b 76 63 65 77 5d 78 6d 5b 76 73 77 5d 78 6d 5b 76 73 77 5d 78 6d 5b 76 77 5d 78 6d 5b 76 22 } //01 00   = "w]xm[vrow]xm[vw]xm[vcew]xm[vsw]xm[vsw]xm[vw]xm[v"
		$a_01_1 = {20 3d 20 22 77 5d 78 6d 5b 76 3a 77 77 5d 78 6d 5b 76 77 5d 78 6d 5b 76 69 6e 77 5d 78 6d 5b 76 33 77 5d 78 6d 5b 76 32 77 5d 78 6d 5b 76 5f 77 5d 78 6d 5b 76 22 } //01 00   = "w]xm[v:ww]xm[vw]xm[vinw]xm[v3w]xm[v2w]xm[v_w]xm[v"
		$a_01_2 = {20 3d 20 22 77 77 5d 78 6d 5b 76 69 6e 77 5d 78 6d 5b 76 6d 77 5d 78 6d 5b 76 67 6d 77 5d 78 6d 5b 76 74 77 5d 78 6d 5b 76 77 5d 78 6d 5b 76 22 } //01 00   = "ww]xm[vinw]xm[vmw]xm[vgmw]xm[vtw]xm[vw]xm[v"
		$a_03_3 = {20 3d 20 52 65 70 6c 61 63 65 28 90 02 20 2c 20 22 77 5d 78 6d 5b 76 22 2c 20 90 02 20 29 90 00 } //01 00 
		$a_03_4 = {2e 43 72 65 61 74 65 20 90 02 20 28 90 02 20 2c 20 90 02 20 2c 20 90 02 20 2c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}