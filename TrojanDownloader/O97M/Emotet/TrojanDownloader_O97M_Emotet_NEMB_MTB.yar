
rule TrojanDownloader_O97M_Emotet_NEMB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.NEMB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 66 71 77 6c 65 6b 6c 6b 6a 28 4f 70 74 69 6f 6e 61 6c 20 42 79 56 61 6c 20 54 69 74 6c 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 20 22 2c 20 5f } //01 00  Function fqwleklkj(Optional ByVal Title As String = " ", _
		$a_01_1 = {44 69 6d 20 67 68 6b 61 66 6a 65 6b 20 41 73 20 44 6f 75 62 6c 65 } //01 00  Dim ghkafjek As Double
		$a_01_2 = {50 72 69 76 61 74 65 20 53 75 62 20 67 66 6c 69 65 77 68 65 6c 28 29 } //01 00  Private Sub gfliewhel()
		$a_01_3 = {73 65 72 76 69 63 65 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 2c 20 22 22 29 2e 52 75 6e 20 72 61 2c 20 30 } //01 00  service.CreateObject("Wscript.Shell", "").Run ra, 0
		$a_01_4 = {4d 73 67 42 6f 78 20 66 6a 6c } //00 00  MsgBox fjl
	condition:
		any of ($a_*)
 
}