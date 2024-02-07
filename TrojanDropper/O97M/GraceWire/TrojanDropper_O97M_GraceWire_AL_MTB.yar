
rule TrojanDropper_O97M_GraceWire_AL_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 53 65 74 52 65 73 6f 75 72 63 65 42 79 74 65 73 28 6c 70 54 79 70 65 20 41 73 20 4c 6f 6e 67 2c 20 6c 70 49 44 20 41 73 20 4c 6f 6e 67 2c 20 6c 70 44 61 74 61 28 29 20 41 73 20 42 79 74 65 2c 20 6c 70 46 69 6c 65 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 4c 6f 6e 67 } //01 00  Public Function SetResourceBytes(lpType As Long, lpID As Long, lpData() As Byte, lpFile As String) As Long
		$a_01_1 = {53 65 74 20 46 75 63 6a 69 46 69 6c 6d 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 22 20 2b 20 22 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  Set FucjiFilm = CreateObject("WScri" + "pt.Shell")
		$a_01_2 = {55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 20 3d 20 46 75 63 6a 69 46 69 6c 6d 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 55 73 65 72 46 6f 72 6d 36 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 29 } //01 00  UserForm6.TextBox3.Tag = FucjiFilm.SpecialFolders(UserForm6.TextBox3.Tag)
		$a_01_3 = {26 20 42 6c 6f 62 53 4e 20 26 20 42 6c 6f 62 43 6e 74 20 26 20 22 2f 22 20 26 20 4d 69 64 28 73 70 6c 69 74 74 65 73 74 28 50 74 72 29 2c 20 50 6f 73 45 6e 64 53 63 72 69 70 74 29 } //00 00  & BlobSN & BlobCnt & "/" & Mid(splittest(Ptr), PosEndScript)
	condition:
		any of ($a_*)
 
}