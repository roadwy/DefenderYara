
rule TrojanDropper_O97M_Hancitor_JOAA_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JOAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 70 70 70 78 28 70 69 6c 69 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub pppx(pili As String)
		$a_01_1 = {43 61 6c 6c 20 6f 69 63 78 28 70 69 6c 69 29 } //1 Call oicx(pili)
		$a_01_2 = {46 61 6c 73 65 2c 20 41 64 64 54 6f 52 65 63 65 6e 74 46 69 6c 65 73 3a 3d 46 61 6c 73 65 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 64 6f 79 6f 75 6b 6e 6f 77 74 68 61 74 74 68 65 67 6f 64 73 6f 66 64 65 61 74 68 6f 6e 6c 79 65 61 74 61 70 70 6c 65 73 3f } //1 False, AddToRecentFiles:=False, PasswordDocument:="doyouknowthatthegodsofdeathonlyeatapples?
		$a_01_3 = {7a 6f 22 20 26 20 22 72 6f 2e 22 20 26 20 22 64 } //1 zo" & "ro." & "d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}