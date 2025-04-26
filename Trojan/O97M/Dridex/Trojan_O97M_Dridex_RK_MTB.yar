
rule Trojan_O97M_Dridex_RK_MTB{
	meta:
		description = "Trojan:O97M/Dridex.RK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 6d 65 73 74 69 6c 28 61 6b 20 41 73 20 53 74 72 69 6e 67 2c 20 74 6b 20 41 73 20 53 74 72 69 6e 67 2c 20 6d 6b 20 41 73 20 53 74 72 69 6e 67 29 } //1 Function mestil(ak As String, tk As String, mk As String)
		$a_01_1 = {6d 65 73 74 69 6c 20 3d 20 52 65 70 6c 61 63 65 28 61 6b 2c 20 74 6b 2c 20 6d 6b 29 } //1 mestil = Replace(ak, tk, mk)
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 54 6f 70 5f 65 6e 67 65 65 6e 28 29 } //1 Function Top_engeen()
		$a_01_3 = {61 20 3d 20 6d 65 73 74 69 6c 28 22 22 20 26 20 4e 5f 6c 69 6f 28 53 70 6c 69 74 28 73 69 6e 5f 61 6e 64 5f 74 67 28 73 69 6e 5f 61 6e 64 5f 74 67 28 43 65 6c 6c 73 28 37 37 2c 20 37 29 29 29 29 29 28 31 29 2c 20 22 43 22 2c 20 22 2f 22 29 } //1 a = mestil("" & N_lio(Split(sin_and_tg(sin_and_tg(Cells(77, 7)))))(1), "C", "/")
		$a_01_4 = {54 6f 70 5f 65 6e 67 65 65 6e 20 3d 20 6d 65 73 74 69 6c 28 22 22 20 26 20 61 2c 20 22 41 22 2c 20 22 2e 22 29 } //1 Top_engeen = mestil("" & a, "A", ".")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}