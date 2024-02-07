
rule TrojanDownloader_BAT_Formbook_KAC_MTB{
	meta:
		description = "TrojanDownloader:BAT/Formbook.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 0b 00 00 01 00 "
		
	strings :
		$a_03_0 = {d6 0b 07 11 90 01 01 31 90 01 01 90 0a 16 00 11 90 01 01 11 90 01 01 07 94 b4 6f 90 01 03 0a 90 01 01 07 17 90 00 } //01 00 
		$a_81_1 = {70 6f 77 65 72 73 68 65 6c 6c } //01 00  powershell
		$a_81_2 = {28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 } //01 00  (New-Object Net.WebClient)
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //01 00  DownloadString
		$a_01_4 = {54 6f 49 6e 74 65 67 65 72 } //01 00  ToInteger
		$a_01_5 = {53 74 72 69 6e 67 42 75 69 6c 64 65 72 } //01 00  StringBuilder
		$a_01_6 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_7 = {54 6f 53 74 72 69 6e 67 } //01 00  ToString
		$a_01_8 = {53 75 62 73 74 72 69 6e 67 } //01 00  Substring
		$a_01_9 = {43 6f 6d 70 61 72 65 53 74 72 69 6e 67 } //01 00  CompareString
		$a_01_10 = {41 64 64 53 65 63 6f 6e 64 73 } //00 00  AddSeconds
	condition:
		any of ($a_*)
 
}