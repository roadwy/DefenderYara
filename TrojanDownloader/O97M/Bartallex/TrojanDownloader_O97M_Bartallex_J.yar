
rule TrojanDownloader_O97M_Bartallex_J{
	meta:
		description = "TrojanDownloader:O97M/Bartallex.J,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6c 65 65 70 20 54 65 78 74 2c 20 45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 20 26 } //1 Sleep Text, Environ$("tmp") &
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 6a 6f 73 65 70 68 } //1 CreateObject("WScript.Shell").Run joseph
		$a_01_2 = {53 75 62 20 53 6c 65 65 70 28 42 79 56 61 6c 20 6a 61 6d 65 73 2c 20 6a 6f 73 65 70 68 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub Sleep(ByVal james, joseph As String)
		$a_01_3 = {54 65 78 74 20 3d 20 22 68 74 22 20 26 20 5f } //1 Text = "ht" & _
		$a_01_4 = {3d 20 22 5c 22 20 26 20 74 65 78 74 31 20 26 20 22 2e 65 78 65 22 } //1 = "\" & text1 & ".exe"
		$a_01_5 = {72 69 63 61 72 64 6f 74 61 6d 61 79 6f } //1 ricardotamayo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}