
rule TrojanDownloader_BAT_AsyncRAT_SN_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRAT.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 6f 75 72 6e 61 6d 65 6e 74 54 72 61 63 6b 65 72 55 49 2e 44 61 73 68 42 6f 61 72 64 2e 72 65 73 6f 75 72 63 65 73 } //2 TournamentTrackerUI.DashBoard.resources
		$a_01_1 = {24 64 39 63 64 66 36 62 65 2d 39 39 32 33 2d 34 63 39 39 2d 61 36 62 64 2d 62 61 39 34 37 62 31 33 64 62 61 34 } //2 $d9cdf6be-9923-4c99-a6bd-ba947b13dba4
		$a_01_2 = {52 65 70 6f 72 74 69 6e 67 20 45 6e 63 6f 64 69 6e 67 } //2 Reporting Encoding
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}