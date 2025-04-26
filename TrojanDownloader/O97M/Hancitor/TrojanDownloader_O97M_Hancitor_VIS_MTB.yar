
rule TrojanDownloader_O97M_Hancitor_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Hancitor.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 69 72 28 52 6f 6f 74 50 61 74 68 20 26 20 22 5c 30 66 69 61 73 53 2e 74 6d 70 22 29 } //1 Dir(RootPath & "\0fiasS.tmp")
		$a_01_1 = {44 69 72 28 76 7a 78 78 20 26 20 22 5c 57 30 72 64 2e 64 6c 6c 22 29 20 3d 20 22 22 } //1 Dir(vzxx & "\W0rd.dll") = ""
		$a_01_2 = {30 66 69 61 73 53 2e 74 22 20 26 20 22 6d 70 22 20 41 73 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 30 72 64 2e 64 6c 6c 22 } //1 0fiasS.t" & "mp" As ActiveDocument.AttachedTemplate.Path & "\" & "W0rd.dll"
		$a_01_3 = {43 61 6c 6c 20 72 65 67 73 72 76 61 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 66 61 2c 20 79 79 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 } //1 Call regsrva.ShellExecute(fa, yy, " ", SW_SHOWNORMAL)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}