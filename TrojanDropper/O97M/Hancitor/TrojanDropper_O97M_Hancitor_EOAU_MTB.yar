
rule TrojanDropper_O97M_Hancitor_EOAU_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOAU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 46 69 6c 65 4e 61 6d 65 3a 3d 76 63 62 63 20 26 20 22 5c 67 6c 69 62 2e 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 2c 20 43 6f 6e 66 69 72 6d 43 6f 6e 76 65 72 73 69 6f 6e 73 3a 3d 46 61 6c 73 65 2c 20 52 65 61 64 4f 6e 6c 79 3a 3d 20 5f } //1 Documents.Open FileName:=vcbc & "\glib.d" & "o" & "c", ConfirmConversions:=False, ReadOnly:= _
		$a_01_1 = {49 66 20 44 69 72 28 76 63 62 63 20 26 20 22 5c 67 6c 69 62 2e 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 29 20 3d 20 22 22 20 54 68 65 6e } //1 If Dir(vcbc & "\glib.d" & "o" & "c") = "" Then
		$a_01_2 = {43 61 6c 6c 20 62 76 78 66 63 73 64 } //1 Call bvxfcsd
		$a_01_3 = {41 64 64 54 6f 52 65 63 65 6e 74 46 69 6c 65 73 3a 3d 46 61 6c 73 65 2c 20 50 61 73 73 77 6f 72 64 44 6f 63 75 6d 65 6e 74 3a 3d 22 31 32 33 33 32 31 22 2c 20 5f } //1 AddToRecentFiles:=False, PasswordDocument:="123321", _
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}