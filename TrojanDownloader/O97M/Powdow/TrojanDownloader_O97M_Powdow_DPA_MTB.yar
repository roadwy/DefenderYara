
rule TrojanDownloader_O97M_Powdow_DPA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DPA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 73 70 6c 69 74 2d 66 22 2b 63 63 75 68 79 7a 73 6d 67 68 6b 2b 22 22 2b 7a 62 6c 6f 77 65 72 6c 2c 30 2c 74 72 75 65 } //1 -split-f"+ccuhyzsmghk+""+zblowerl,0,true
		$a_01_1 = {3d 78 78 77 72 38 28 22 65 78 65 2e 62 66 75 79 74 77 62 79 75 36 63 78 73 68 6c 2f 6d 65 72 2f 6d 6f 63 2e 6e 72 75 74 71 65 74 2f 2f 3a 73 70 74 74 68 22 29 } //1 =xxwr8("exe.bfuytwbyu6cxshl/mer/moc.nrutqet//:sptth")
		$a_01_2 = {77 72 38 26 6d 69 64 28 78 78 77 72 39 2c 63 65 6e 79 30 2c 31 29 6c 66 6f } //1 wr8&mid(xxwr9,ceny0,1)lfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}