
rule TrojanDropper_O97M_Hancitor_HAG_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.HAG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 20 6a 73 64 20 26 } //01 00  & jsd &
		$a_01_1 = {26 20 22 44 6c 6c 22 20 26 20 22 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 22 } //01 00  & "Dll" & "UnregisterServer"
		$a_01_2 = {61 73 64 66 20 3d 20 52 6f 6f 74 50 61 74 68 } //01 00  asdf = RootPath
		$a_01_3 = {79 61 2e 77 61 76 } //01 00  ya.wav
		$a_01_4 = {57 30 72 64 2e 64 6c 6c } //01 00  W0rd.dll
		$a_01_5 = {26 20 22 5c 79 61 2e 77 61 76 22 20 41 73 20 66 75 } //01 00  & "\ya.wav" As fu
		$a_01_6 = {43 61 6c 6c 20 67 6f 74 6f 64 6f 77 6e } //01 00  Call gotodown
		$a_01_7 = {53 75 62 20 67 6f 74 6f 64 6f 77 6e 28 29 } //01 00  Sub gotodown()
		$a_01_8 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //01 00  Set fld = fso.GetFolder(asdf)
		$a_03_9 = {46 6f 72 20 45 61 63 68 20 90 02 06 20 49 6e 20 66 6c 64 2e 53 55 42 46 4f 4c 44 45 52 53 90 00 } //01 00 
		$a_01_10 = {26 20 22 5c 79 61 2e 77 61 76 22 20 41 73 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22 } //00 00  & "\ya.wav" As ActiveDocument.AttachedTemplate.Path & "\" & "W0rd.dll"
	condition:
		any of ($a_*)
 
}