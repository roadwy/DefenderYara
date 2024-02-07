
rule TrojanDownloader_O97M_EncDoc_PAAM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {76 62 5f 6e 61 6d 65 3d 22 6d 6f 64 75 6c 65 33 22 64 69 6d } //01 00  vb_name="module3"dim
		$a_01_1 = {70 6c 66 3d 22 2e 22 69 66 64 69 72 28 75 75 26 22 5c 6d 6f 65 78 78 22 26 70 6c 66 26 22 62 22 26 22 69 22 26 22 6e 22 2c } //01 00  plf="."ifdir(uu&"\moexx"&plf&"b"&"i"&"n",
		$a_01_2 = {63 3d 62 62 76 76 3d 22 70 2e 22 26 76 66 65 6e 64 73 75 62 73 75 62 78 63 76 73 64 66 73 28 29 63 61 6c 6c 6d 6d 28 22 64 6f 64 72 6f 37 2e 72 22 26 22 75 2f 22 29 65 6e 64 73 75 62 73 75 62 64 73 73 64 66 28 29 64 69 6d 6b 6c 78 61 73 73 74 72 69 6e 67 6b 6c 78 3d 22 74 22 63 61 6c 6c 6d 6d 28 22 68 22 26 22 74 22 26 6b 6c 78 29 65 } //00 00  c=bbvv="p."&vfendsubsubxcvsdfs()callmm("dodro7.r"&"u/")endsubsubdssdf()dimklxasstringklx="t"callmm("h"&"t"&klx)e
	condition:
		any of ($a_*)
 
}