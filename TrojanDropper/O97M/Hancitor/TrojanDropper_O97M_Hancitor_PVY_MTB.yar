
rule TrojanDropper_O97M_Hancitor_PVY_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.PVY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {49 66 20 44 69 72 28 6a 73 61 20 26 20 22 5c 22 20 26 20 22 57 30 22 20 26 20 22 72 64 2e 64 22 20 26 20 22 6c 6c 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(jsa & "\" & "W0" & "rd.d" & "ll") = "" Then
		$a_00_1 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //1 Set fld = fso.GetFolder(asdf)
		$a_00_2 = {6a 73 61 20 3d 20 72 65 70 69 64 } //1 jsa = repid
		$a_00_3 = {43 61 6c 6c 20 72 6e 65 65 28 75 75 75 2c 20 61 61 61 61 29 } //1 Call rnee(uuu, aaaa)
		$a_00_4 = {53 75 62 20 68 68 68 68 68 } //1 Sub hhhhh
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}