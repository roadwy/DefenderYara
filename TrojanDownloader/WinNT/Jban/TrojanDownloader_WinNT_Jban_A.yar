
rule TrojanDownloader_WinNT_Jban_A{
	meta:
		description = "TrojanDownloader:WinNT/Jban.A,SIGNATURE_TYPE_JAVAHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f } //10 dl.dropbox.com/u/
		$a_03_1 = {57 10 08 b8 00 ?? b6 00 ?? 12 ?? b6 00 90 1b 01 12 ?? b6 00 90 1b 01 12 ?? b6 00 90 1b 01 b6 00 ?? 3a } //1
		$a_00_2 = {41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 } //1 ALLUSERSPROFILE
	condition:
		((#a_00_0  & 1)*10+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=12
 
}