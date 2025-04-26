
rule TrojanDownloader_O97M_Powdow_GM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.GM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 72 6d 20 3d 20 62 66 68 64 67 33 37 64 72 74 33 74 28 22 21 55 30 21 5a 21 45 30 21 4f 30 21 5a 21 44 30 21 66 64 6a 70 69 64 21 44 30 21 22 29 } //1 prm = bfhdg37drt3t("!U0!Z!E0!O0!Z!D0!fdjpid!D0!")
		$a_00_1 = {74 6d 70 73 20 3d 20 62 66 68 64 67 33 37 64 72 74 33 74 28 22 74 71 6e 75 5d 73 6a 65 71 6e 75 5d 64 6a 22 20 26 20 22 6d 63 76 51 5d 74 73 66 74 56 5d 3b 44 22 29 } //1 tmps = bfhdg37drt3t("tqnu]sjeqnu]dj" & "mcvQ]tsftV];D")
		$a_00_2 = {63 74 20 3d 20 44 61 74 65 44 69 66 66 28 22 73 22 2c 20 22 31 2f 31 2f 31 39 37 30 22 2c 20 44 61 74 65 20 2b 20 54 69 6d 65 29 } //1 ct = DateDiff("s", "1/1/1970", Date + Time)
		$a_00_3 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d } //1 Attribute VB_Name =
		$a_00_4 = {44 65 63 6c 61 72 65 20 53 75 62 20 47 6f 6f 64 4e 69 67 68 74 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 53 6c 65 65 70 22 20 28 42 79 56 61 6c 20 6d 69 6c 6c 69 73 65 63 6f 6e 64 73 20 41 73 20 4c 6f 6e 67 29 } //1 Declare Sub GoodNight Lib "kernel32" Alias "Sleep" (ByVal milliseconds As Long)
		$a_00_5 = {44 69 6d 20 74 6d 70 73 20 41 73 20 53 74 72 69 6e 67 } //1 Dim tmps As String
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}