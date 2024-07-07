
rule TrojanDownloader_O97M_Tnega_PRB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Tnega.PRB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 } //1 = ActiveDocument.Path & "\" & ActiveDocument.Name
		$a_00_1 = {3d 20 63 75 72 44 6f 63 4e 61 6d 65 20 26 20 22 20 2e 64 6f 63 78 22 } //1 = curDocName & " .docx"
		$a_00_2 = {77 6f 72 6b 44 69 72 20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 50 72 6f 66 69 6c 65 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 6e 65 4e 6f 74 65 22 } //1 workDir = Environ("UserProfile") & "\AppData\Local\Microsoft\OneNote"
		$a_00_3 = {64 6c 6c 50 61 74 68 20 3d 20 77 6f 72 6b 44 69 72 20 26 20 22 5c 6f 6e 65 6e 6f 74 65 2e 64 62 22 } //1 dllPath = workDir & "\onenote.db"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}