
rule TrojanDownloader_O97M_Restenga_A_dha{
	meta:
		description = "TrojanDownloader:O97M/Restenga.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 70 70 64 61 74 61 6c 6f 63 61 74 69 6f 6e 65 6e 76 69 72 6f 6e 6c 6f 63 61 6c 61 70 70 64 61 74 61 6d 69 63 72 6f 73 6f 66 74 74 65 61 6d 73 63 75 72 72 65 6e 74 75 70 64 61 74 65 7a 69 70 64 65 73 74 69 6e 61 74 69 6f 65 6e 76 69 72 6f 6e 6c 6f 63 61 6c 61 70 70 64 61 74 61 6d 69 63 72 6f 73 6f 66 74 74 65 61 6d 73 } //1 appdatalocationenvironlocalappdatamicrosoftteamscurrentupdatezipdestinatioenvironlocalappdatamicrosoftteams
		$a_00_1 = {74 72 75 65 73 68 65 6c 6c 28 22 63 6d 64 2e 65 78 65 2f 63 63 64 25 6c 6f 63 61 6c 61 70 70 64 61 74 61 25 5c 6d 69 63 72 6f 73 6f 66 74 5c 74 65 61 6d 73 5c 63 75 72 72 65 6e 74 5c 26 77 6f 72 6b 66 6f 6c 64 65 72 73 2e 65 78 65 } //1 trueshell("cmd.exe/ccd%localappdata%\microsoft\teams\current\&workfolders.exe
		$a_00_2 = {73 68 2e 6e 61 6d 65 73 70 61 63 65 28 64 65 73 74 69 6e 61 74 69 6f 29 2e 63 6f 70 79 68 65 72 65 73 68 2e 6e 61 6d 65 73 70 61 63 65 28 6c 6f 63 61 74 69 6f 6e 29 2e 69 74 65 6d 73 } //1 sh.namespace(destinatio).copyheresh.namespace(location).items
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}