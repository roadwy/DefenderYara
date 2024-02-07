
rule TrojanDownloader_Win32_Zlob_ANP{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANP,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0f 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 69 73 73 69 6e 67 77 6f 72 6c 64 } //01 00  missingworld
		$a_01_1 = {6e 6e 65 63 74 41 } //01 00  nnectA
		$a_01_2 = {72 6e 65 74 43 6f } //01 00  rnetCo
		$a_01_3 = {44 49 52 20 22 25 73 22 } //01 00  DIR "%s"
		$a_01_4 = {74 6f 20 61 67 } //01 00  to ag
		$a_01_5 = {49 53 54 20 22 25 73 22 } //01 00  IST "%s"
		$a_01_6 = {44 45 4c 20 22 25 73 22 } //01 00  DEL "%s"
		$a_01_7 = {77 65 77 74 25 64 2e 62 61 74 } //01 00  wewt%d.bat
		$a_01_8 = {5f 49 45 56 55 } //01 00  _IEVU
		$a_01_9 = {5f 7e 3f 64 75 6d 62 } //01 00  _~?dumb
		$a_01_10 = {25 64 6d 69 73 73 69 6e 67 77 6f 72 6c 64 } //01 00  %dmissingworld
		$a_01_11 = {6d 67 66 75 79 70 75 62 65 6e } //01 00  mgfuypuben
		$a_01_12 = {7c 44 45 4c 20 44 49 52 20 } //01 00  |DEL DIR 
		$a_01_13 = {2e 74 65 61 5f } //01 00  .tea_
		$a_01_14 = {3a 31 77 65 77 74 5f 2e 62 } //00 00  :1wewt_.b
	condition:
		any of ($a_*)
 
}