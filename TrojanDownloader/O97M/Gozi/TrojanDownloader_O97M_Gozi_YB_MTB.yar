
rule TrojanDownloader_O97M_Gozi_YB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Gozi.YB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {6d 33 33 78 61 33 2e 63 6f 6d 2f 68 62 6f 6e 65 62 2f 73 6f 6c [0-04] 2e 70 68 70 3f 6c 3d 70 75 6f 6d } //1
		$a_00_1 = {43 38 2e 74 6d 70 } //1 C8.tmp
		$a_00_2 = {58 64 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 72 65 67 73 76 } //1 Xd As String = "regsv
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}