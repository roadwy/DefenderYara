
rule TrojanDownloader_Win32_Agent_DO{
	meta:
		description = "TrojanDownloader:Win32/Agent.DO,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 4c 53 49 44 20 3d 20 73 20 27 7b 41 42 43 44 45 43 46 30 2d 34 42 31 35 2d 31 31 44 31 2d 41 42 45 44 2d 37 30 39 35 34 39 43 31 30 30 30 30 7d 27 } //01 00  CLSID = s '{ABCDECF0-4B15-11D1-ABED-709549C10000}'
		$a_01_1 = {2f 73 65 61 72 63 68 2e 70 68 70 3f 71 3d 25 73 26 61 64 76 3d 25 64 26 69 64 3d 25 64 26 73 3d 25 64 } //01 00  /search.php?q=%s&adv=%d&id=%d&s=%d
		$a_01_2 = {31 30 74 72 75 73 74 65 64 73 69 74 65 73 2e 63 6f 6d } //01 00  10trustedsites.com
		$a_01_3 = {74 6f 70 31 30 73 65 61 72 63 68 65 73 2e 6e 65 74 } //01 00  top10searches.net
		$a_01_4 = {74 6f 70 32 30 73 65 61 72 63 68 65 73 2e 6e 65 74 } //01 00  top20searches.net
		$a_01_5 = {49 00 45 00 48 00 65 00 6c 00 70 00 65 00 72 00 } //01 00  IEHelper
		$a_01_6 = {43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 74 65 78 74 2f 68 74 6d 6c 3b 20 63 68 61 72 73 65 74 3d 55 54 46 2d 38 } //01 00  Content-Type: text/html; charset=UTF-8
		$a_01_7 = {73 65 61 72 63 68 2e 6d 73 6e 2e 63 6f 6d 2f 72 65 73 75 6c 74 73 2e 61 73 70 78 } //01 00  search.msn.com/results.aspx
		$a_01_8 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //00 00  InternetReadFile
	condition:
		any of ($a_*)
 
}