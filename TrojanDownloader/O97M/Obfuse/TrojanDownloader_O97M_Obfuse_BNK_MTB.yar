
rule TrojanDownloader_O97M_Obfuse_BNK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.BNK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 57 28 43 4c 6e 67 28 28 4e 6f 74 } //1 ChrW(CLng((Not
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 } //1 Debug.Print
		$a_01_2 = {3d 20 49 73 44 61 74 65 28 43 4c 6e 67 } //1 = IsDate(CLng
		$a_01_3 = {3d 20 49 45 66 76 4b 68 47 63 59 7a 64 70 2e 5a 32 44 71 37 5f 62 4e 30 35 } //1 = IEfvKhGcYzdp.Z2Dq7_bN05
		$a_01_4 = {3d 20 4c 65 6e 28 4a 6f 69 6e 28 41 72 72 61 79 28 50 39 44 55 4d 5f 59 34 49 76 5f 54 4e 38 5f 46 62 52 56 } //1 = Len(Join(Array(P9DUM_Y4Iv_TN8_FbRV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}