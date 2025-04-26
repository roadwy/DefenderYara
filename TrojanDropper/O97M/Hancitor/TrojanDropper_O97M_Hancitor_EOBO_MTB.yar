
rule TrojanDropper_O97M_Hancitor_EOBO_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 61 6c 73 65 2c 20 41 64 64 54 6f 52 65 63 65 6e 74 46 69 6c 65 73 3a 3d 46 61 6c 73 65 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 32 32 38 31 33 33 37 22 2c 20 5f } //1 False, AddToRecentFiles:=False, PasswordDocument:="2281337", _
		$a_01_1 = {66 66 66 66 66 20 3d 20 22 64 69 70 6c 6f 2e 69 22 20 26 20 73 69 70 6c 6f } //1 fffff = "diplo.i" & siplo
		$a_01_2 = {43 61 6c 6c 20 75 6f 69 61 28 61 61 61 61 29 } //1 Call uoia(aaaa)
		$a_01_3 = {43 61 6c 6c 20 73 32 28 22 63 61 6c 2f 22 29 } //1 Call s2("cal/")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}