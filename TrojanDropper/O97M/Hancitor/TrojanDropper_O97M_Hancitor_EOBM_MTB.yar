
rule TrojanDropper_O97M_Hancitor_EOBM_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 6e 61 6d 28 70 61 66 73 20 41 73 20 53 74 72 69 6e 67 2c 20 61 61 61 61 20 41 73 20 53 74 72 69 6e 67 29 } //01 00  Sub nam(pafs As String, aaaa As String)
		$a_01_1 = {43 61 6c 6c 20 6f 75 73 78 28 61 61 61 61 29 } //01 00  Call ousx(aaaa)
		$a_01_2 = {44 69 6d 20 61 62 72 61 6b 61 64 61 62 72 61 20 41 73 20 53 74 72 69 6e 67 } //01 00  Dim abrakadabra As String
		$a_01_3 = {61 62 72 61 6b 61 64 61 62 72 61 20 3d 20 22 6f 22 } //01 00  abrakadabra = "o"
		$a_01_4 = {61 62 72 61 6b 61 64 61 62 72 61 20 3d 20 61 62 72 61 6b 61 64 61 62 72 61 20 26 20 22 63 22 } //01 00  abrakadabra = abrakadabra & "c"
		$a_01_5 = {44 69 6d 20 6f 78 6c } //01 00  Dim oxl
		$a_01_6 = {6f 78 6c 20 3d 20 22 5c 64 69 70 6c 6f 2e 64 22 20 26 20 61 62 72 61 6b 61 64 61 62 72 61 } //00 00  oxl = "\diplo.d" & abrakadabra
	condition:
		any of ($a_*)
 
}