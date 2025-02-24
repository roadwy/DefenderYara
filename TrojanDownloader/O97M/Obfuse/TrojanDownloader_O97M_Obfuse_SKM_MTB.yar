
rule TrojanDownloader_O97M_Obfuse_SKM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SKM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 64 6f 63 20 28 74 6d 70 20 26 20 22 5c 22 20 26 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 20 26 20 22 2e 64 6f 63 22 29 } //1 rundoc (tmp & "\" & ActiveDocument.Name & ".doc")
		$a_01_1 = {3d 20 77 73 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 6c 6f 63 61 6c 61 70 70 22 20 26 20 22 64 61 74 61 25 5c 54 22 20 26 20 22 65 6d 70 22 29 } //1 = wsl.ExpandEnvironmentStrings("%localapp" & "data%\T" & "emp")
		$a_01_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 55 6e 70 72 6f 74 65 63 74 20 28 22 6f 69 6b 6d 73 65 4d 23 2a 69 6e 6d 6f 77 65 66 6a 38 33 34 39 61 6e 33 22 29 } //1 ActiveDocument.Unprotect ("oikmseM#*inmowefj8349an3")
		$a_01_3 = {46 6f 72 20 69 20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 2e 43 6f 75 6e 74 20 54 6f 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 2e 43 6f 75 6e 74 20 2b 20 31 20 2d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 63 74 69 76 65 57 69 6e 64 6f 77 2e 50 61 6e 65 73 28 31 29 2e 50 61 67 65 73 2e 43 6f 75 6e 74 20 2a 20 32 20 53 74 65 70 20 2d 31 } //1 For i = ActiveDocument.Shapes.Count To ActiveDocument.Shapes.Count + 1 - ActiveDocument.ActiveWindow.Panes(1).Pages.Count * 2 Step -1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}