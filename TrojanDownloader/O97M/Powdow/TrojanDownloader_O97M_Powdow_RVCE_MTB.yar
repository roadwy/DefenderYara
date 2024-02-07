
rule TrojanDownloader_O97M_Powdow_RVCE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 2f 67 61 6c 6c 61 67 68 65 72 73 65 61 6c 73 2e 6d 6c 2f 64 6f 63 2f 77 65 6e 6f 7a 70 78 6e 66 71 2e 65 78 65 27 22 65 78 3d 22 6d 65 64 69 61 2e 65 78 65 27 3b } //01 00  //gallagherseals.ml/doc/wenozpxnfq.exe'"ex="media.exe';
		$a_01_1 = {73 68 65 6c 6c 68 68 68 68 2b 28 22 22 2b 73 73 73 73 2b 67 67 67 67 2b 22 3b 69 6e 76 6f 6b 65 2d 69 74 65 6d 24 6d 6d 6d 6d 6d 6d 22 29 65 6e 64 73 75 62 } //01 00  shellhhhh+(""+ssss+gggg+";invoke-item$mmmmmm")endsub
		$a_01_2 = {72 65 70 6c 61 63 65 28 68 68 68 68 2c 22 61 64 22 2c 22 73 68 65 22 29 68 68 68 68 3d 72 65 70 6c 61 63 65 28 68 68 68 68 2c 22 2e 65 78 65 22 2c 22 6c 6c 22 29 } //00 00  replace(hhhh,"ad","she")hhhh=replace(hhhh,".exe","ll")
	condition:
		any of ($a_*)
 
}