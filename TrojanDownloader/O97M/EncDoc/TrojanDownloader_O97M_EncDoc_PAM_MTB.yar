
rule TrojanDownloader_O97M_EncDoc_PAM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 63 6e 6c 22 66 75 6e 63 74 69 6f 6e 6c 6a 6b 6e 6d 6e } //1 vb_name="cnl"functionljknmn
		$a_01_1 = {6c 6a 6b 6e 6d 6e 3d 63 68 72 28 6f 70 68 6a 69 2d 31 33 30 29 76 63 78 62 64 67 } //1 ljknmn=chr(ophji-130)vcxbdg
		$a_01_2 = {2e 72 75 6e 28 6e 75 6a 76 66 74 69 64 78 2c } //1 .run(nujvftidx,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}