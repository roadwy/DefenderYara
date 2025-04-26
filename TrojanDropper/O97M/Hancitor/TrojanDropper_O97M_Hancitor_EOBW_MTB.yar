
rule TrojanDropper_O97M_Hancitor_EOBW_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 44 69 72 28 66 64 73 20 26 20 22 7a 6f 22 20 26 20 22 72 6f 22 20 26 20 66 64 73 61 20 26 20 76 73 73 66 73 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(fds & "zo" & "ro" & fdsa & vssfs) = "" Then
		$a_01_1 = {6d 79 53 75 6d 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 70 70 6c 22 29 } //1 mySum = Application.Run("ppl")
		$a_01_2 = {43 61 6c 6c 20 70 70 70 78 28 66 64 73 20 26 20 22 7a 6f 22 20 26 20 22 72 6f 22 20 26 20 66 64 73 61 20 26 20 76 73 73 66 73 29 } //1 Call pppx(fds & "zo" & "ro" & fdsa & vssfs)
		$a_01_3 = {43 61 6c 6c 20 61 73 73 } //1 Call ass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}