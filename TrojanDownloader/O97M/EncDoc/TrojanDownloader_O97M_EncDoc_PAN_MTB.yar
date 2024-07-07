
rule TrojanDownloader_O97M_EncDoc_PAN_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 6f 63 75 6d 65 6e 74 73 5c 22 2b 22 74 6c 6c 73 6d 34 77 32 2e 74 78 74 22 29 74 68 65 6e 69 66 6e 6f 74 6e 62 68 78 32 38 79 77 2e 66 6f 6c 64 65 72 65 78 69 73 74 73 28 6e 78 39 6e 66 67 70 79 29 74 68 65 6e 6e 62 68 78 32 38 79 77 2e 63 72 65 61 74 65 66 6f 6c 64 65 72 28 6e 78 39 6e 66 67 70 79 29 71 73 3d 6e 78 39 6e 66 67 70 79 2b 22 5c 68 65 6c 70 63 65 6e 74 65 72 75 70 64 61 74 65 72 2e 76 62 73 } //1 documents\"+"tllsm4w2.txt")thenifnotnbhx28yw.folderexists(nx9nfgpy)thennbhx28yw.createfolder(nx9nfgpy)qs=nx9nfgpy+"\helpcenterupdater.vbs
		$a_01_1 = {77 72 69 74 65 22 72 7a 30 6b 32 74 33 6b 3d 73 70 6c 69 74 28 73 74 72 2c 22 22 63 32 22 22 2c 2d 31 2c 30 29 22 26 76 62 } //1 write"rz0k2t3k=split(str,""c2"",-1,0)"&vb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}