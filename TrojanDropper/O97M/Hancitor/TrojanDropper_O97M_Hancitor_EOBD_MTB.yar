
rule TrojanDropper_O97M_Hancitor_EOBD_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 72 65 66 6f 72 6d 2e 64 6f 63 22 } //1 \reform.doc"
		$a_01_1 = {53 75 62 20 70 70 70 78 28 73 70 6f 63 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub pppx(spoc As String)
		$a_01_2 = {46 61 6c 73 65 2c 20 41 64 64 54 6f 52 65 63 65 6e 74 46 69 6c 65 73 3a 3d 46 61 6c 73 65 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 32 32 38 31 33 33 37 22 2c 20 5f } //1 False, AddToRecentFiles:=False, PasswordDocument:="2281337", _
		$a_01_3 = {43 61 6c 6c 20 75 6f 69 61 28 61 61 61 61 29 } //1 Call uoia(aaaa)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}