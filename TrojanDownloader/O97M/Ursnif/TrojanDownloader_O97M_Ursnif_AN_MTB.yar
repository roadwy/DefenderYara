
rule TrojanDownloader_O97M_Ursnif_AN_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {26 20 22 5c [0-10] 2e 78 22 } //1
		$a_03_1 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-08] 2c 20 [0-06] 2c 20 [0-06] 29 29 } //1
		$a_03_2 = {3d 20 22 74 [0-01] 6d 70 22 } //1
		$a_01_3 = {3d 20 22 22 } //1 = ""
		$a_01_4 = {22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 "bin.base64"
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}