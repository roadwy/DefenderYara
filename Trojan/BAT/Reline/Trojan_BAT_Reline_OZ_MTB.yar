
rule Trojan_BAT_Reline_OZ_MTB{
	meta:
		description = "Trojan:BAT/Reline.OZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 70 00 68 00 79 00 73 00 69 00 63 00 90 02 02 63 00 72 00 61 00 66 00 74 00 2e 00 75 00 73 00 2f 00 4d 00 69 00 6e 00 65 00 63 00 72 00 61 00 66 00 74 00 90 02 12 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_01_1 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 3b 00 63 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 2f 00 6d 00 61 00 69 00 6e 00 77 00 69 00 6e 00 64 00 6f 00 77 00 2e 00 78 00 61 00 6d 00 6c 00 } //01 00  DownloadFile;component/mainwindow.xaml
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 41 73 79 6e 63 } //01 00  DownloadFileAsync
		$a_81_3 = {61 64 64 5f 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 43 6f 6d 70 6c 65 74 65 64 } //01 00  add_DownloadFileCompleted
		$a_81_4 = {5f 63 6f 6e 74 65 6e 74 4c 6f 61 64 65 64 } //01 00  _contentLoaded
		$a_81_5 = {73 65 74 5f 55 73 65 53 68 65 6c 6c 45 78 65 63 75 74 65 } //01 00  set_UseShellExecute
		$a_81_6 = {6c 69 6e 71 } //01 00  linq
		$a_81_7 = {46 49 4c 45 4e 41 4d 45 } //01 00  FILENAME
		$a_81_8 = {73 65 74 5f 53 74 61 72 74 75 70 55 72 69 } //01 00  set_StartupUri
		$a_81_9 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 2e 70 64 62 } //00 00  DownloadFile.pdb
	condition:
		any of ($a_*)
 
}