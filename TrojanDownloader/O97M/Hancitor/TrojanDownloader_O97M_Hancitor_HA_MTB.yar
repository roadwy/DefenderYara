
rule TrojanDownloader_O97M_Hancitor_HA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Hancitor.HA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {6e 74 67 73 29 20 26 20 22 4c 6f 63 22 20 26 20 22 61 6c 5c 54 65 22 20 26 20 22 6d 70 22 2c 20 76 62 44 69 72 65 63 74 6f 72 79 29 20 3d } //1 ntgs) & "Loc" & "al\Te" & "mp", vbDirectory) =
		$a_00_1 = {47 65 74 6d 65 28 52 6f 6f 74 50 61 74 68 20 41 73 20 53 74 72 69 6e 67 29 } //1 Getme(RootPath As String)
		$a_00_2 = {3d 20 66 73 6f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 66 29 } //1 = fso.GetFolder(asdf)
		$a_00_3 = {44 69 72 28 52 6f 6f 74 50 61 74 68 20 26 20 22 5c 32 32 2e 6d 70 34 22 29 } //1 Dir(RootPath & "\22.mp4")
		$a_00_4 = {47 65 74 6d 65 28 76 68 68 73 2e 50 61 74 68 29 } //1 Getme(vhhs.Path)
		$a_00_5 = {50 61 74 68 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 29 20 3d 20 22 22 } //1 Path & "\W0rd.dll") = ""
		$a_00_6 = {43 61 6c 6c 20 6c 6b 61 28 52 6f 6f 74 50 61 74 68 29 } //1 Call lka(RootPath)
		$a_00_7 = {4e 61 6d 65 20 55 55 75 20 26 20 22 5c 32 32 2e 6d 70 34 } //1 Name UUu & "\22.mp4
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}