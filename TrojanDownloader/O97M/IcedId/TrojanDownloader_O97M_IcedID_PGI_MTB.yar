
rule TrojanDownloader_O97M_IcedID_PGI_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PGI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 72 69 6d 28 61 4a 72 52 77 79 20 26 20 22 74 20 3a 20 22 20 26 20 61 72 53 78 77 20 26 20 61 56 54 6f 4b 30 20 26 20 61 72 53 78 77 29 } //01 00  Trim(aJrRwy & "t : " & arSxw & aVToK0 & arSxw)
		$a_00_1 = {43 61 6c 6c 20 61 7a 4b 46 74 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 61 35 6d 72 65 2c 20 61 67 72 70 30 2c 20 22 20 22 2c 20 53 57 5f 53 48 4f 57 4e 4f 52 4d 41 4c 29 } //01 00  Call azKFt.ShellExecute(a5mre, agrp0, " ", SW_SHOWNORMAL)
		$a_00_2 = {61 35 34 58 67 4e 20 3d 20 53 70 6c 69 74 28 61 45 37 33 42 69 28 66 72 6d 2e 70 61 74 68 73 2e 74 65 78 74 29 2c 20 22 7c 22 29 } //01 00  a54XgN = Split(aE73Bi(frm.paths.text), "|")
		$a_00_3 = {43 61 6c 6c 20 61 46 33 78 4f 2e 43 6f 70 79 46 69 6c 65 28 61 6c 56 58 59 78 2c 20 61 79 33 7a 69 2c 20 31 29 } //01 00  Call aF3xO.CopyFile(alVXYx, ay3zi, 1)
		$a_00_4 = {61 51 4a 4e 74 73 20 3d 20 53 74 72 43 6f 6e 76 28 62 2c 20 76 62 55 6e 69 63 6f 64 65 29 } //01 00  aQJNts = StrConv(b, vbUnicode)
		$a_00_5 = {61 51 59 4e 44 20 3d 20 61 51 59 4e 44 20 26 20 22 22 20 26 20 4d 69 64 28 61 46 77 43 69 2c 20 61 67 35 74 55 70 2c 20 31 29 } //00 00  aQYND = aQYND & "" & Mid(aFwCi, ag5tUp, 1)
	condition:
		any of ($a_*)
 
}