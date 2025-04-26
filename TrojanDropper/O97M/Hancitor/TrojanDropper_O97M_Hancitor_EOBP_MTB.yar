
rule TrojanDropper_O97M_Hancitor_EOBP_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 20 70 70 70 78 28 6b 79 74 72 65 77 77 66 20 26 20 22 5c 64 69 70 6c 6f 2e 64 22 20 26 20 61 62 72 61 6b 61 64 61 62 72 61 29 } //1 Call pppx(kytrewwf & "\diplo.d" & abrakadabra)
		$a_01_1 = {43 61 6c 6c 20 70 70 70 78 28 6b 79 74 72 65 77 77 66 20 26 20 66 64 73 20 26 20 22 64 69 22 20 26 20 22 70 6c 6f 22 20 26 20 66 64 73 61 20 26 20 76 73 73 66 73 29 } //1 Call pppx(kytrewwf & fds & "di" & "plo" & fdsa & vssfs)
		$a_01_2 = {44 69 6d 20 76 76 31 2c 20 76 76 32 2c 20 76 76 33 2c 20 76 76 34 2c 20 66 61 66 61 61 20 41 73 20 53 74 72 69 6e 67 } //1 Dim vv1, vv2, vv3, vv4, fafaa As String
		$a_01_3 = {49 66 20 44 69 72 28 4c 65 66 74 28 75 75 75 75 63 2c 20 6e 74 67 73 29 20 26 20 6b 75 6c 73 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(Left(uuuuc, ntgs) & kuls, vbDirectory) = "" Then
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}