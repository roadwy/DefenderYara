
rule TrojanDownloader_BAT_PromCoinminer_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/PromCoinminer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 6d 72 62 66 69 6c 65 2e 78 79 7a 2f 73 71 6c 2f 73 79 73 6c 69 62 2e 64 6c 6c } //01 00  http://mrbfile.xyz/sql/syslib.dll
		$a_81_1 = {5c 53 65 63 75 72 69 74 79 53 65 72 76 69 63 65 5c 53 65 63 75 72 69 74 79 53 65 72 76 69 63 65 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 57 69 6e 64 6f 77 73 53 65 63 75 72 69 74 79 53 65 72 76 69 63 65 2e 70 64 62 } //01 00  \SecurityService\SecurityService\obj\Release\WindowsSecurityService.pdb
		$a_81_2 = {5c 63 6f 6e 66 69 67 2e 6a 73 6f 6e } //01 00  \config.json
		$a_81_3 = {5c 76 65 72 73 69 6f 6e 2e 74 78 74 } //01 00  \version.txt
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 44 4c 4c } //01 00  DownloadDLL
		$a_81_5 = {43 6f 70 79 5a 69 70 46 69 6c 65 } //00 00  CopyZipFile
	condition:
		any of ($a_*)
 
}