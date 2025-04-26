
rule TrojanDropper_O97M_Hancitor_EOAV_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOAV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 66 66 66 66 20 3d 20 22 67 6c 69 62 2e 62 22 20 26 20 22 61 78 22 } //1 fffff = "glib.b" & "ax"
		$a_01_1 = {6f 78 6c 20 3d 20 22 5c 67 6c 69 62 2e 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 } //1 oxl = "\glib.d" & "o" & "c"
		$a_01_2 = {65 77 72 77 73 64 66 20 3d 20 65 77 72 77 73 64 66 20 26 20 22 54 65 6d 70 22 } //1 ewrwsdf = ewrwsdf & "Temp"
		$a_01_3 = {43 61 6c 6c 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 68 64 68 64 64 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 65 77 72 77 73 64 66 29 } //1 Call ThisDocument.hdhdd(Left(uuuuc, ntgs) & ewrwsdf)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}