
rule TrojanDownloader_Linux_Donoff_H{
	meta:
		description = "TrojanDownloader:Linux/Donoff.H,SIGNATURE_TYPE_MACROHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 65 63 65 6e 74 46 69 6c 65 73 2e 43 6f 75 6e 74 20 3c 20 33 20 54 68 65 6e 20 4d 6f 64 75 6c 65 31 2e } //4 If Application.RecentFiles.Count < 3 Then Module1.
		$a_01_1 = {45 72 72 2e 52 61 69 73 65 20 4e 75 6d 62 65 72 3a 3d 34 2c 20 44 65 73 63 72 69 70 74 69 6f 6e 3a 3d 73 28 } //2 Err.Raise Number:=4, Description:=s(
		$a_01_2 = {5a 4d 77 62 2e 4f 70 65 6e 28 73 28 22 54 45 47 22 2c 20 31 37 2c 20 32 33 29 2c } //3 ZMwb.Open(s("TEG", 17, 23),
		$a_01_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 73 28 42 79 56 61 6c 20 74 57 5a 47 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 66 42 70 70 20 41 73 20 49 6e 74 65 67 65 72 2c } //2 Public Function s(ByVal tWZG As String, ByVal fBpp As Integer,
		$a_01_4 = {63 4f 75 68 20 3d 20 5a 4d 77 62 2e 52 65 73 70 6f 6e 73 65 54 65 78 74 } //3 cOuh = ZMwb.ResponseText
		$a_01_5 = {50 75 62 6c 69 63 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 43 6c 6f 73 65 28 29 } //1 Public Sub Document_Close()
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1) >=15
 
}