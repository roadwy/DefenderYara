
rule TrojanDownloader_O97M_Qakbot_PBB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PBB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 46 53 4f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  Set FSO = CreateObject("Scripting.FileSystemObject")
		$a_00_1 = {46 53 4f 2e 43 6f 70 79 46 69 6c 65 20 61 51 42 6d 62 2c 20 61 42 48 4d 44 63 2c 20 31 } //01 00  FSO.CopyFile aQBmb, aBHMDc, 1
		$a_00_2 = {61 30 65 35 38 43 20 3d 20 53 70 6c 69 74 28 61 75 36 76 73 54 28 66 72 6d 2e 70 61 74 68 73 2e 74 65 78 74 29 2c 20 22 7c 22 29 } //01 00  a0e58C = Split(au6vsT(frm.paths.text), "|")
		$a_00_3 = {44 69 6d 20 61 50 72 75 45 4e 20 41 73 20 4e 65 77 20 53 68 65 6c 6c 33 32 2e 53 68 65 6c 6c } //01 00  Dim aPruEN As New Shell32.Shell
		$a_00_4 = {43 61 6c 6c 20 61 50 72 75 45 4e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 61 68 38 55 41 2c 20 61 51 69 6f 58 46 2c 20 22 20 22 2c 20 53 57 5f 48 49 44 45 29 } //01 00  Call aPruEN.ShellExecute(ah8UA, aQioXF, " ", SW_HIDE)
		$a_00_5 = {61 44 42 56 4a 33 20 3d 20 61 75 36 76 73 54 28 66 72 6d 2e 70 61 79 6c 6f 61 64 2e 74 65 78 74 29 } //01 00  aDBVJ3 = au6vsT(frm.payload.text)
		$a_00_6 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 61 57 6f 31 49 33 22 2c 20 61 42 48 4d 44 63 2c 20 61 64 44 4d 63 20 26 20 22 6d 61 74 20 3a 20 22 22 22 20 26 20 61 4c 59 43 56 20 26 20 22 22 22 22 } //00 00  Application.Run "aWo1I3", aBHMDc, adDMc & "mat : """ & aLYCV & """"
	condition:
		any of ($a_*)
 
}