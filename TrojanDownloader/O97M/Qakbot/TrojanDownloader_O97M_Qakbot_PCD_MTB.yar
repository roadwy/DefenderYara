
rule TrojanDownloader_O97M_Qakbot_PCD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.PCD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 70 6c 69 74 28 61 39 48 36 34 28 66 72 6d 2e 70 61 74 68 73 2e 74 65 78 74 29 2c 20 22 7c 22 29 } //1 Split(a9H64(frm.paths.text), "|")
		$a_00_1 = {43 61 6c 6c 20 61 68 77 74 55 6d 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 61 4b 34 53 54 2c 20 61 36 73 44 39 2c 20 22 20 22 2c 20 53 57 5f 48 49 44 45 29 } //1 Call ahwtUm.ShellExecute(aK4ST, a6sD9, " ", SW_HIDE)
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 61 39 34 36 38 75 22 2c 20 61 50 4b 4a 74 31 2c 20 61 50 46 59 54 20 26 20 22 6d 61 74 20 3a 20 22 20 26 20 61 37 43 6e 39 47 20 26 20 61 52 62 4d 74 20 26 20 61 37 43 6e 39 47 } //1 Application.Run "a9468u", aPKJt1, aPFYT & "mat : " & a7Cn9G & aRbMt & a7Cn9G
		$a_00_3 = {3d 20 61 39 48 36 34 28 66 72 6d 2e 70 61 79 6c 6f 61 64 2e 74 65 78 74 29 } //1 = a9H64(frm.payload.text)
		$a_00_4 = {53 65 74 20 46 53 4f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 Set FSO = CreateObject("Scripting.FileSystemObject")
		$a_00_5 = {46 53 4f 2e 43 6f 70 79 46 69 6c 65 20 61 34 65 77 50 71 2c 20 61 50 4b 4a 74 31 2c 20 31 } //1 FSO.CopyFile a4ewPq, aPKJt1, 1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}