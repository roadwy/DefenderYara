
rule TrojanDownloader_O97M_Powdow_D_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.D!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 22 } //1 Private Declare PtrSafe Function CreateProcess Lib "kernel32" Alias "CreateProcessA"
		$a_01_1 = {3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 28 7a 61 73 78 64 63 66 76 2c 20 53 74 72 52 65 76 65 72 73 65 28 4c 65 66 74 24 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 53 68 61 70 65 73 28 22 54 65 78 74 20 42 6f 78 20 32 22 29 2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 2c } //1 = CreateProcess(zasxdcfv, StrReverse(Left$(ActiveDocument.Shapes("Text Box 2").TextFrame.TextRange.Text,
		$a_01_2 = {2e 54 65 78 74 46 72 61 6d 65 2e 54 65 78 74 52 61 6e 67 65 2e 54 65 78 74 29 20 2d 20 31 29 29 2c 20 42 79 56 61 6c 20 30 26 2c 20 42 79 56 61 6c 20 30 26 2c 20 31 26 } //1 .TextFrame.TextRange.Text) - 1)), ByVal 0&, ByVal 0&, 1&
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}