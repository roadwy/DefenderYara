
rule TrojanDropper_O97M_Hancitor_EOBA_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOBA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 5c 67 6c 22 20 26 20 22 69 62 2e 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 } //1 "\gl" & "ib.d" & "o" & "c"
		$a_01_1 = {43 61 6c 6c 20 75 6f 69 61 28 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 55 73 65 72 54 65 6d 70 6c 61 74 65 73 50 61 74 68 29 29 } //1 Call uoia(Options.DefaultFilePath(wdUserTemplatesPath))
		$a_01_2 = {53 75 62 20 70 70 70 78 28 73 70 6f 63 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub pppx(spoc As String)
		$a_01_3 = {46 61 6c 73 65 2c 20 41 64 64 54 6f 52 65 63 65 6e 74 46 69 6c 65 73 3a 3d 46 61 6c 73 65 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 31 32 33 33 32 31 22 2c 20 5f } //1 False, AddToRecentFiles:=False, PasswordDocument:="123321", _
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}