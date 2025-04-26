
rule TrojanDownloader_O97M_Powdow_ALL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ALL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 67 44 6c 6b 59 4e 48 57 69 4b 6a 6b 6e 74 4a 59 6f 64 68 71 57 6b 62 34 36 46 64 66 28 29 20 41 73 20 53 69 6e 67 6c 65 } //1 Function gDlkYNHWiKjkntJYodhqWkb46Fdf() As Single
		$a_01_1 = {43 61 6c 6c 20 6b 62 66 44 49 6b 6a 48 4a 4b 4e } //1 Call kbfDIkjHJKN
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 22 20 26 } //1 = Environ$("USERPROFILE") & "\" &
		$a_01_3 = {52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 22 50 6c 65 61 73 65 20 77 61 69 74 22 } //1 Range("A1").Value = "Please wait"
		$a_01_4 = {4d 73 67 42 6f 78 20 22 50 6c 65 61 73 65 20 77 61 69 74 22 } //1 MsgBox "Please wait"
		$a_01_5 = {53 65 74 20 6f 62 6a 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set objWshShell = CreateObject("WScript.Shell")
		$a_01_6 = {6f 62 6a 57 73 68 53 68 65 6c 6c 2e 50 6f 70 75 70 20 22 47 65 74 74 69 6e 67 20 72 65 73 6f 75 63 72 63 65 73 20 74 6f 20 64 69 73 70 6c 61 79 20 73 70 72 65 65 64 73 68 65 65 74 22 2c 20 2c 20 22 4f 4b 22 } //1 objWshShell.Popup "Getting resoucrces to display spreedsheet", , "OK"
		$a_01_7 = {53 70 65 63 69 61 6c 50 61 74 68 20 3d 20 6f 62 6a 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 54 65 6d 70 6c 61 74 65 73 22 29 } //1 SpecialPath = objWshShell.SpecialFolders("Templates")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}