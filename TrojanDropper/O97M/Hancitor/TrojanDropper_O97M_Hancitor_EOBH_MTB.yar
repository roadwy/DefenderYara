
rule TrojanDropper_O97M_Hancitor_EOBH_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 6e 61 6d 28 70 61 66 73 20 41 73 20 53 74 72 69 6e 67 2c 20 61 61 61 61 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub nam(pafs As String, aaaa As String)
		$a_01_1 = {43 61 6c 6c 20 6f 75 73 78 28 61 61 61 61 29 } //1 Call ousx(aaaa)
		$a_01_2 = {44 69 6d 20 6f 78 6c } //1 Dim oxl
		$a_01_3 = {6f 78 6c 20 3d 20 22 5c 72 65 66 6f 72 6d 22 20 26 20 22 2e 64 6f 63 22 } //1 oxl = "\reform" & ".doc"
		$a_01_4 = {4e 61 6d 65 20 70 61 66 73 20 41 73 20 70 6c 73 20 26 20 6f 78 6c } //1 Name pafs As pls & oxl
		$a_01_5 = {53 75 62 20 75 6f 69 61 28 66 66 66 73 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub uoia(fffs As String)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}