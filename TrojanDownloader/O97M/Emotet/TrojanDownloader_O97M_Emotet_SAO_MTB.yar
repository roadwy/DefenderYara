
rule TrojanDownloader_O97M_Emotet_SAO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SAO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {20 3d 20 22 41 5d 5b 71 5b 44 72 6f 41 5d 5b 71 5b 44 41 5d 5b 71 5b 44 63 65 41 5d 5b 71 5b 44 73 41 5d 5b 71 5b 44 73 41 5d 5b 71 5b 44 41 5d 5b 71 5b 44 22 } //01 00   = "A][q[DroA][q[DA][q[DceA][q[DsA][q[DsA][q[DA][q[D"
		$a_01_1 = {20 3d 20 22 41 5d 5b 71 5b 44 3a 77 41 5d 5b 71 5b 44 41 5d 5b 71 5b 44 69 6e 41 5d 5b 71 5b 44 33 41 5d 5b 71 5b 44 32 41 5d 5b 71 5b 44 5f 41 5d 5b 71 5b 44 22 } //01 00   = "A][q[D:wA][q[DA][q[DinA][q[D3A][q[D2A][q[D_A][q[D"
		$a_01_2 = {20 3d 20 22 77 41 5d 5b 71 5b 44 69 6e 41 5d 5b 71 5b 44 6d 41 5d 5b 71 5b 44 67 6d 41 5d 5b 71 5b 44 74 41 5d 5b 71 5b 44 41 5d 5b 71 5b 44 22 } //01 00   = "wA][q[DinA][q[DmA][q[DgmA][q[DtA][q[DA][q[D"
		$a_03_3 = {20 3d 20 52 65 70 6c 61 63 65 28 90 02 20 2c 20 22 41 5d 5b 71 5b 44 22 2c 20 90 02 20 29 90 00 } //01 00 
		$a_01_4 = {3d 20 22 41 5d 5b 71 5b 44 70 41 5d 5b 71 5b 44 22 } //01 00  = "A][q[DpA][q[D"
		$a_03_5 = {2e 43 72 65 61 74 65 20 90 02 20 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}