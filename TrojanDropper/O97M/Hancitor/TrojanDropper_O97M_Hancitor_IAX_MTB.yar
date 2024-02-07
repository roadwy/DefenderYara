
rule TrojanDropper_O97M_Hancitor_IAX_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.IAX!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 22 20 26 20 22 30 22 20 26 20 22 72 22 20 26 20 22 64 2e 64 } //01 00  W" & "0" & "r" & "d.d
		$a_01_1 = {2e 64 22 20 26 20 22 6c 22 20 26 20 22 6c } //01 00  .d" & "l" & "l
		$a_01_2 = {26 20 6a 73 64 20 26 20 22 6c 6c 22 20 26 20 68 68 } //01 00  & jsd & "ll" & hh
		$a_01_3 = {43 61 6c 6c 20 73 74 65 74 70 74 77 77 6f } //01 00  Call stetptwwo
		$a_01_4 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //01 00  Set fld = fso.GetFolder(asdf)
		$a_01_5 = {57 6f 72 64 2e 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 } //01 00  Word.ActiveDocument.AttachedTemplate.Path
		$a_01_6 = {44 69 6d 20 6a 73 61 20 41 73 20 53 74 72 69 6e 67 } //00 00  Dim jsa As String
	condition:
		any of ($a_*)
 
}