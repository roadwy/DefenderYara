
rule TrojanDownloader_O97M_Qakbot_AZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.AZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 61 57 6f 31 49 33 22 2c 20 61 67 46 69 5a 2c 20 61 6c 66 68 75 76 20 26 20 22 6d 61 74 20 3a 20 22 22 22 20 26 20 61 52 79 4f 4e 20 26 20 22 22 22 22 } //01 00  Application.Run "aWo1I3", agFiZ, alfhuv & "mat : """ & aRyON & """"
		$a_00_1 = {61 78 51 67 36 52 20 3d 20 61 75 36 76 73 54 28 66 72 6d 2e 70 61 79 6c 6f 61 64 2e 74 65 78 74 29 } //01 00  axQg6R = au6vsT(frm.payload.text)
		$a_00_2 = {43 61 6c 6c 20 61 43 75 32 34 51 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 61 4e 45 58 73 2c 20 61 4b 4c 6e 6a 54 2c 20 22 20 22 2c 20 53 57 5f 48 49 44 45 29 } //01 00  Call aCu24Q.ShellExecute(aNEXs, aKLnjT, " ", SW_HIDE)
		$a_00_3 = {61 6f 7a 65 78 20 3d 20 53 70 6c 69 74 28 61 75 36 76 73 54 28 66 72 6d 2e 70 61 74 68 73 2e 74 65 78 74 29 2c 20 22 7c 22 29 } //01 00  aozex = Split(au6vsT(frm.paths.text), "|")
		$a_00_4 = {53 65 74 20 46 53 4f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //01 00  Set FSO = CreateObject("Scripting.FileSystemObject")
		$a_00_5 = {46 53 4f 2e 43 6f 70 79 46 69 6c 65 20 61 59 67 75 73 2c 20 61 67 46 69 5a 2c 20 31 } //00 00  FSO.CopyFile aYgus, agFiZ, 1
	condition:
		any of ($a_*)
 
}