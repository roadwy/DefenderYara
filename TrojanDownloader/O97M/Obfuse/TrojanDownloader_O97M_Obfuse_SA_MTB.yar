
rule TrojanDownloader_O97M_Obfuse_SA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 } //01 00  'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox
		$a_01_1 = {53 65 74 20 6f 62 6a 53 74 61 72 74 75 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //01 00  Set objStartup = CreateObject("winmgmts:Win32_ProcessStartup")
		$a_01_2 = {3d 20 6f 50 72 6f 63 65 73 73 2e 4d 65 74 68 6f 64 73 5f 28 22 43 72 65 61 74 65 22 29 2e 20 5f } //01 00  = oProcess.Methods_("Create"). _
		$a_01_3 = {41 74 20 28 70 2e 56 61 6c 75 65 29 } //01 00  At (p.Value)
		$a_01_4 = {57 6f 72 6b 73 68 65 65 74 73 28 31 29 2e 41 63 74 69 76 61 74 65 } //00 00  Worksheets(1).Activate
	condition:
		any of ($a_*)
 
}