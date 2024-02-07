
rule TrojanDownloader_O97M_TrickBot_PTA_MTB{
	meta:
		description = "TrojanDownloader:O97M/TrickBot.PTA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 68 50 77 54 37 72 47 4b 2e 45 78 65 63 } //01 00  EhPwT7rGK.Exec
		$a_00_1 = {70 55 75 53 65 4c 4f 70 6b 20 28 22 63 3a 5c 55 54 46 38 4e 6f 42 4f 4d 22 29 } //01 00  pUuSeLOpk ("c:\UTF8NoBOM")
		$a_00_2 = {72 69 79 75 6f 79 75 6f 2e 43 6c 6f 73 65 } //01 00  riyuoyuo.Close
		$a_00_3 = {4d 6b 44 69 72 20 6e 66 67 66 6d 67 68 79 6b 74 72 6c } //01 00  MkDir nfgfmghyktrl
		$a_00_4 = {66 67 68 66 6a 66 67 6a 72 6b 72 6b 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 } //00 00  fghfjfgjrkrk.CreateTextFile(
	condition:
		any of ($a_*)
 
}