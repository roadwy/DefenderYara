
rule TrojanDownloader_Win64_ShellcodeLoader_RP_MTB{
	meta:
		description = "TrojanDownloader:Win64/ShellcodeLoader.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 00 75 00 6f 00 72 00 6f 00 6e 00 67 00 71 00 6e 00 6d 00 6c 00 62 00 } //01 00  huorongqnmlb
		$a_01_1 = {68 00 75 00 6f 00 72 00 6f 00 6e 00 67 00 } //01 00  huorong
		$a_01_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 57 } //01 00  InternetOpenW
		$a_01_3 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 57 } //01 00  InternetOpenUrlW
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //00 00  InternetReadFile
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win64_ShellcodeLoader_RP_MTB_2{
	meta:
		description = "TrojanDownloader:Win64/ShellcodeLoader.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {48 83 ec 18 c7 04 24 8a 00 00 00 c7 44 24 04 9d 07 00 00 8b 04 24 99 83 e0 01 33 c2 2b c2 8b 0c 24 ff c1 89 0c 24 85 c0 7e 0e } //01 00 
		$a_01_1 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 57 } //01 00  InternetOpenW
		$a_01_2 = {49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c 57 } //01 00  InternetOpenUrlW
		$a_01_3 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //00 00  InternetReadFile
	condition:
		any of ($a_*)
 
}