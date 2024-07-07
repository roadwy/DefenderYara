
rule TrojanDropper_O97M_Hancitor_EOBY_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 5c 7a 6f 72 6f 2e 22 20 26 20 22 64 } //1 = "\zoro." & "d
		$a_01_1 = {3d 20 22 7a 6f 72 6f 2e 6b 6c 22 20 54 68 65 6e } //1 = "zoro.kl" Then
		$a_01_2 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 64 68 64 64 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 74 69 6e 69 29 } //1 Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & tini)
		$a_01_3 = {43 61 6c 6c 20 53 65 61 72 63 68 28 4d 79 46 53 4f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 61 29 2c 20 6c 64 73 29 } //1 Call Search(MyFSO.GetFolder(asda), lds)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}