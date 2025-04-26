
rule Trojan_O97M_QuasarRAT_RDA_MTB{
	meta:
		description = "Trojan:O97M/QuasarRAT.RDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 20 3d 20 4d 69 64 28 65 6e 63 2c 20 79 2c 20 31 29 } //2 w = Mid(enc, y, 1)
		$a_01_1 = {41 70 70 44 61 74 61 20 3d 20 41 70 70 44 61 74 61 20 26 20 43 68 72 28 41 73 63 28 77 29 20 2d 20 31 29 } //2 AppData = AppData & Chr(Asc(w) - 1)
		$a_01_2 = {65 6e 63 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 65 6e 63 29 } //2 enc = StrReverse(enc)
		$a_01_3 = {44 65 63 72 79 70 74 69 6e 6b 6e 20 3d 20 41 70 70 44 61 74 61 } //2 Decryptinkn = AppData
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}