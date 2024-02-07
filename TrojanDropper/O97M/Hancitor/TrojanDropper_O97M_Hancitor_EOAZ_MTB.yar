
rule TrojanDropper_O97M_Hancitor_EOAZ_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EOAZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 67 6c 69 62 2e 64 22 20 26 20 22 6f 22 20 26 20 22 63 22 } //01 00  \glib.d" & "o" & "c"
		$a_01_1 = {53 75 62 20 70 70 70 78 28 73 70 6f 63 20 41 73 20 53 74 72 69 6e 67 29 } //01 00  Sub pppx(spoc As String)
		$a_01_2 = {44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 46 69 6c 65 4e 61 6d 65 3a 3d 73 70 6f 63 2c 20 43 6f 6e 66 69 72 6d 43 6f 6e 76 65 72 73 69 6f 6e 73 3a 3d 46 61 6c 73 65 2c 20 52 65 61 64 4f 6e 6c 79 3a 3d 20 5f } //01 00  Documents.Open FileName:=spoc, ConfirmConversions:=False, ReadOnly:= _
		$a_01_3 = {43 61 6c 6c 20 75 6f 69 61 28 4f 70 74 69 6f 6e 73 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 28 77 64 55 73 65 72 54 65 6d 70 6c 61 74 65 73 50 61 74 68 29 29 } //01 00  Call uoia(Options.DefaultFilePath(wdUserTemplatesPath))
		$a_01_4 = {53 75 62 20 6f 75 73 78 28 29 } //00 00  Sub ousx()
	condition:
		any of ($a_*)
 
}