
rule TrojanDropper_O97M_Hancitor_EOBQ_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 44 69 72 28 6b 79 74 72 65 77 77 66 20 26 20 66 64 73 20 26 20 22 64 69 22 20 26 20 22 70 6c 6f 22 20 26 20 66 64 73 61 20 26 20 76 73 73 66 73 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(kytrewwf & fds & "di" & "plo" & fdsa & vssfs) = "" Then
		$a_01_1 = {66 64 73 61 20 3d 20 22 2e 64 22 } //1 fdsa = ".d"
		$a_01_2 = {43 61 6c 6c 20 75 6f 69 61 28 61 61 61 61 29 } //1 Call uoia(aaaa)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}