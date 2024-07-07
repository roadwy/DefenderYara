
rule TrojanDropper_O97M_Hancitor_JAN_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.JAN!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 74 69 63 2e 64 6c 6c } //1 Static.dll
		$a_01_1 = {43 61 6c 6c 20 73 74 65 74 70 74 77 77 6f } //1 Call stetptwwo
		$a_01_2 = {43 61 6c 6c 20 68 68 68 68 68 } //1 Call hhhhh
		$a_01_3 = {26 20 6a 73 64 20 26 } //1 & jsd &
		$a_01_4 = {44 69 6d 20 72 65 67 73 72 76 61 20 41 73 20 4e 65 77 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c } //1 Dim regsrva As New Shell32.Shell
		$a_01_5 = {44 69 6d 20 67 65 74 6f 20 41 73 20 53 74 72 69 6e 67 } //1 Dim geto As String
		$a_01_6 = {44 69 6d 20 70 75 73 20 41 73 20 53 74 72 69 6e 67 } //1 Dim pus As String
		$a_01_7 = {43 61 6c 6c 20 6e 6d 28 6f 6c 6f 6c 6f 77 29 } //1 Call nm(ololow)
		$a_01_8 = {53 65 74 20 66 6c 64 20 3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //1 Set fld = fso.GetFolder(asdf)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}