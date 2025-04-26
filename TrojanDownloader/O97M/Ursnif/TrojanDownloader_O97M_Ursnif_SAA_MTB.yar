
rule TrojanDownloader_O97M_Ursnif_SAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.SAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 28 53 65 59 29 29 2e 47 65 74 28 28 53 79 49 29 29 } //1 = GetObject((SeY)).Get((SyI))
		$a_01_1 = {3d 20 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 65 28 48 61 42 42 28 22 28 21 70 7a 72 79 33 73 6f 2e 26 68 3a 70 63 72 74 2f 6f 6d 76 74 2f 78 6f 22 29 2c 20 66 6f 29 } //1 = Internationale(HaBB("(!pzry3so.&h:pcrt/omvt/xo"), fo)
		$a_01_2 = {3d 20 48 61 42 42 28 22 5f 35 4d 4d 50 30 2c 4c 4c 2e 49 4d 32 48 36 66 58 58 54 30 68 53 2e 54 2e 22 29 } //1 = HaBB("_5MMP0,LL.IM2H6fXXT0hS.T.")
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 22 20 26 20 54 54 29 } //1 = CreateObject("" & TT)
		$a_01_4 = {2e 57 72 69 74 65 20 77 6f 6c 46 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 3a 20 2e 53 61 76 65 54 6f 46 69 6c 65 20 47 75 6d 56 75 2c } //1 .Write wolF.responseBody: .SaveToFile GumVu,
		$a_01_5 = {3d 20 4e 65 77 20 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 36 30 } //1 = New MSXML2.XMLHTTP60
		$a_01_6 = {2e 4f 70 65 6e 20 22 22 20 26 20 52 59 2c 20 56 69 55 2c 20 46 61 6c 73 65 2c 20 22 22 2c } //1 .Open "" & RY, ViU, False, "",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}