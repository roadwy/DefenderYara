
rule TrojanDownloader_O97M_Powdow_DPB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DPB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 72 70 78 67 75 77 72 38 28 22 65 78 65 2e 75 6a 6a 32 66 34 31 64 66 31 66 35 30 61 65 2f 6e 69 6c 62 6f 67 2f 6d 6f 63 2e 6e 72 75 74 71 65 74 2f 2f 3a 73 70 74 74 68 22 29 } //1 =rpxguwr8("exe.ujj2f41df1f50ae/nilbog/moc.nrutqet//:sptth")
		$a_01_1 = {2d 73 70 6c 69 74 2d 66 22 2b 74 70 71 6c 2b 22 22 2b 63 76 63 6a 62 2c 30 2c 74 72 75 65 } //1 -split-f"+tpql+""+cvcjb,0,true
		$a_01_2 = {66 6f 72 61 75 65 61 30 3d 6c 65 6e 28 72 70 78 67 75 77 72 39 29 74 6f 31 73 74 65 70 2d 31 7a 6f 73 77 7a 71 62 74 6b 70 62 73 6b 64 72 3d } //1 forauea0=len(rpxguwr9)to1step-1zoswzqbtkpbskdr=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}