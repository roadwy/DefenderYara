
rule TrojanDownloader_O97M_Donoff_MXR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MXR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //2 CreateObject("Shell.Application")
		$a_01_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 } //2 ShellExecute "P" + 
		$a_01_2 = {4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 } //2 MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox
		$a_01_3 = {70 20 3d 20 4c 65 6e 28 73 29 20 54 6f 20 31 20 53 74 65 70 20 2d 31 } //2 p = Len(s) To 1 Step -1
		$a_01_4 = {4d 69 64 28 73 2c 20 70 2c 20 31 29 } //2 Mid(s, p, 1)
		$a_01_5 = {46 6f 72 20 69 20 3d 20 31 20 54 6f 20 56 42 41 2e 4c 65 6e } //2 For i = 1 To VBA.Len
		$a_01_6 = {77 65 72 73 68 65 6c 6c } //2 wershell
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}