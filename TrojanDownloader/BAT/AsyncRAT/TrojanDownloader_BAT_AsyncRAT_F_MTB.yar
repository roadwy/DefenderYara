
rule TrojanDownloader_BAT_AsyncRAT_F_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 61 00 68 00 6d 00 65 00 64 00 73 00 79 00 61 00 6d 00 6f 00 7a 00 6f 00 2e 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  ://ahmedsyamozo.er.exe
		$a_01_1 = {2f 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  /explorer.exe
		$a_01_2 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_4 = {53 68 65 6c 6c } //01 00  Shell
		$a_01_5 = {41 70 70 57 69 6e 53 74 79 6c 65 } //00 00  AppWinStyle
	condition:
		any of ($a_*)
 
}