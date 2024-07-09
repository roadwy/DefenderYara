
rule TrojanDownloader_O97M_Obfuse_PSTT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 61 63 72 6f 36 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 20 3d 20 22 20 5c 6e 31 34 22 } //1 Macro6.VB_ProcData.VB_Invoke_Func = " \n14"
		$a_03_1 = {2e 63 6f 6d 2f 61 63 74 69 76 65 2f 73 65 61 72 63 68 4d 65 73 73 65 6e 67 65 72 2f 64 77 2e 70 68 70 3f 6d 6f 64 65 3d 65 74 63 22 2c 90 0a 50 00 46 69 6c 65 5f 44 6f 77 6e 4c 6f 61 64 20 22 68 74 74 70 3a 2f 2f 77 77 77 2e 79 65 73 66 6f 72 6d } //1
		$a_01_2 = {53 68 65 6c 6c 20 22 43 3a 5c 73 4d 65 73 73 65 6e 67 65 72 5c 73 65 61 72 63 68 4d 65 73 73 65 6e 67 65 72 5f 75 70 67 72 61 64 65 5f 78 2e 65 78 65 22 } //1 Shell "C:\sMessenger\searchMessenger_upgrade_x.exe"
		$a_01_3 = {41 63 74 69 76 65 53 68 65 65 74 2e 55 6e 70 72 6f 74 65 63 74 20 50 61 73 73 77 6f 72 64 20 3d 20 31 32 33 34 } //1 ActiveSheet.Unprotect Password = 1234
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Obfuse_PSTT_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.PSTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 6f 6d 65 67 61 68 5f 33 2c 20 76 62 48 69 64 65 46 6f 63 75 73 29 3a } //1 = Shell(omegah_3, vbHideFocus):
		$a_01_1 = {3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 46 75 6c 6c 4e 61 6d 65 3a 20 53 68 65 6c 6c 20 28 22 63 6d 64 2e 65 78 65 20 2f 43 20 20 22 22 22 20 2b 20 6f 6d 65 67 61 68 5f 39 20 2b 20 22 22 22 22 29 } //1 = Application.ActiveWorkbook.FullName: Shell ("cmd.exe /C  """ + omegah_9 + """")
		$a_01_2 = {28 72 2c 20 22 22 31 31 53 66 3a 2f 2f 78 75 4e 6b 49 56 58 37 2e 54 69 2f 57 56 5f 6a 52 69 4a 63 6c 2f 41 66 76 6f 72 26 4e 46 67 75 6c 72 26 51 42 2e 66 4d 59 3f 31 34 3d 26 6d 71 30 4e 41 66 79 6d 74 30 4b 41 66 22 22 2c } //1 (r, ""11Sf://xuNkIVX7.Ti/WV_jRiJcl/Afvor&NFgulr&QB.fMY?14=&mq0NAfymt0KAf"",
		$a_01_3 = {22 78 3a 5c 66 48 64 49 58 70 42 5c 33 55 52 59 5c 6e 47 6a 75 6c 6f 7a 2e 33 41 69 22 } //1 "x:\fHdIXpB\3URY\nGjuloz.3Ai"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}