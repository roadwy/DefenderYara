
rule TrojanDropper_O97M_SilverMob_D_dha{
	meta:
		description = "TrojanDropper:O97M/SilverMob.D!dha,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 28 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 } //1 Documents.Open (Environ("temp")
		$a_00_1 = {6f 62 6a 45 6d 62 65 64 64 65 64 44 6f 63 2e 53 61 76 65 41 73 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 73 74 72 45 6d 62 65 64 64 65 64 44 6f 63 4e 61 6d 65 } //1 objEmbeddedDoc.SaveAs Environ("temp") & "\" & strEmbeddedDocName
		$a_00_2 = {42 69 6e 4e 61 6d 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 74 65 6d 70 22 29 20 26 20 22 5c 64 77 6d 2e 65 78 65 22 } //1 BinName = Environ("temp") & "\dwm.exe"
		$a_00_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 CreateObject("WScript.Shell")
		$a_00_4 = {6f 62 6a 2e 52 75 6e 20 42 69 6e 4e 61 6d 65 20 26 } //1 obj.Run BinName &
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}