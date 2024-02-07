
rule TrojanDownloader_O97M_Ursnif_AEG_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AEG!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0e 00 0e 00 0e 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 63 6c 61 73 73 4c 69 73 74 20 3d 20 63 6c 61 73 73 4c 69 73 74 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 70 74 72 50 74 72 29 } //01 00  Set classList = classList.CreateTextFile(ptrPtr)
		$a_01_1 = {63 6c 61 73 73 4c 69 73 74 2e 57 72 69 74 65 4c 69 6e 65 20 63 6f 6e 73 74 41 72 72 61 79 44 6f 63 75 6d 65 6e 74 } //01 00  classList.WriteLine constArrayDocument
		$a_01_2 = {50 75 62 6c 69 63 20 53 75 62 20 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b 28 29 } //01 00  Public Sub CommandButton1_Click()
		$a_01_3 = {53 65 74 20 63 6f 75 6e 74 49 6e 64 65 78 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 22 20 26 20 73 63 72 69 70 74 20 26 20 22 73 68 65 6c 6c 22 29 } //01 00  Set countIndex = CreateObject("w" & script & "shell")
		$a_01_4 = {63 6f 75 6e 74 49 6e 64 65 78 2e 65 78 65 63 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 2e 54 61 67 20 26 20 22 20 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6d 61 69 6e 2e 68 74 61 } //01 00  countIndex.exec frm.CommandButton1.Tag & " c:\users\public\main.hta
		$a_01_5 = {77 69 6e 64 6f 77 43 6f 70 79 20 3d 20 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 6d 61 69 6e 2e 68 74 61 22 } //01 00  windowCopy = "c:\users\public\main.hta"
		$a_01_6 = {72 65 6d 6f 76 65 4c 6f 63 61 6c 2e 6d 61 69 6e 43 6c 61 73 73 20 77 69 6e 64 6f 77 43 6f 70 79 2c 20 72 65 70 6f 51 75 65 72 79 } //01 00  removeLocal.mainClass windowCopy, repoQuery
		$a_01_7 = {43 61 6c 6c 20 66 72 6d 2e 43 6f 6d 6d 61 6e 64 42 75 74 74 6f 6e 31 5f 43 6c 69 63 6b } //01 00  Call frm.CommandButton1_Click
		$a_01_8 = {46 75 6e 63 74 69 6f 6e 20 72 65 70 6f 51 75 65 72 79 28 29 } //01 00  Function repoQuery()
		$a_01_9 = {53 65 74 20 67 65 6e 65 72 69 63 44 61 74 61 54 65 78 74 62 6f 78 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 79 73 74 65 6d 2e 54 65 78 74 2e 53 74 72 69 6e 67 42 75 69 6c 64 65 72 22 29 } //01 00  Set genericDataTextbox = CreateObject("System.Text.StringBuilder")
		$a_01_10 = {73 63 72 69 70 74 20 3d 20 22 73 63 72 69 70 74 22 20 26 20 22 2e } //01 00  script = "script" & ".
		$a_01_11 = {67 65 6e 65 72 69 63 44 61 74 61 54 65 78 74 62 6f 78 2e 41 70 70 65 6e 64 5f 33 20 22 } //01 00  genericDataTextbox.Append_3 "
		$a_01_12 = {7b 72 65 74 75 72 6e 20 71 75 65 72 79 47 6c 6f 62 61 6c 43 61 70 74 69 6f 6e 2e 73 70 6c 69 74 28 27 27 29 2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 3b } //01 00  {return queryGlobalCaption.split('').reverse().join('');
		$a_01_13 = {63 6c 61 73 73 54 61 62 6c 65 43 6f 6e 73 74 2e 54 69 6d 65 6f 75 74 20 3d 20 36 30 30 30 30 } //00 00  classTableConst.Timeout = 60000
	condition:
		any of ($a_*)
 
}