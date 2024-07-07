
rule TrojanDownloader_O97M_Powdow_RVCE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 79 6d 61 63 72 6f 28 29 64 69 6d 6d 79 75 72 6c 61 73 73 74 72 69 6e 67 6d 79 75 72 6c 3d 22 68 74 74 70 3a 2f 2f 77 77 77 2e 73 68 69 65 6c 64 77 69 73 65 2e 6f 6e 6c 69 6e 65 2f 75 70 64 61 74 65 63 68 65 63 6b 2e 65 78 65 22 } //1 mymacro()dimmyurlasstringmyurl="http://www.shieldwise.online/updatecheck.exe"
		$a_01_1 = {6f 73 74 72 65 61 6d 2e 63 6c 6f 73 65 65 6e 64 69 66 70 61 74 68 3d 22 75 70 64 61 74 65 63 68 65 63 6b 2e 65 78 65 22 73 68 65 6c 6c 70 61 74 68 2c 76 62 68 69 64 65 65 6e 64 73 75 62 } //1 ostream.closeendifpath="updatecheck.exe"shellpath,vbhideendsub
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Powdow_RVCE_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 67 61 6c 6c 61 67 68 65 72 73 65 61 6c 73 2e 6d 6c 2f 64 6f 63 2f 77 65 6e 6f 7a 70 78 6e 66 71 2e 65 78 65 27 22 65 78 3d 22 6d 65 64 69 61 2e 65 78 65 27 3b } //1 //gallagherseals.ml/doc/wenozpxnfq.exe'"ex="media.exe';
		$a_01_1 = {73 68 65 6c 6c 68 68 68 68 2b 28 22 22 2b 73 73 73 73 2b 67 67 67 67 2b 22 3b 69 6e 76 6f 6b 65 2d 69 74 65 6d 24 6d 6d 6d 6d 6d 6d 22 29 65 6e 64 73 75 62 } //1 shellhhhh+(""+ssss+gggg+";invoke-item$mmmmmm")endsub
		$a_01_2 = {72 65 70 6c 61 63 65 28 68 68 68 68 2c 22 61 64 22 2c 22 73 68 65 22 29 68 68 68 68 3d 72 65 70 6c 61 63 65 28 68 68 68 68 2c 22 2e 65 78 65 22 2c 22 6c 6c 22 29 } //1 replace(hhhh,"ad","she")hhhh=replace(hhhh,".exe","ll")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}