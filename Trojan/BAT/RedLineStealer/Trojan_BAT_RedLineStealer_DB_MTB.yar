
rule Trojan_BAT_RedLineStealer_DB_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //01 00  //cdn.discordapp.com/attachments/
		$a_81_1 = {53 74 65 61 6d 43 6c 6f 75 64 46 69 6c 65 4d 61 6e 61 67 65 72 4c 69 74 65 2e 75 70 6c 6f 61 64 } //01 00  SteamCloudFileManagerLite.upload
		$a_81_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_81_4 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 } //01 00  WindowsFormsApp
		$a_81_5 = {49 6e 6a 65 63 74 69 6f 6e 20 48 6f 73 74 3a } //01 00  Injection Host:
		$a_81_6 = {4e 69 72 6d 61 6c 61 20 55 49 } //01 00  Nirmala UI
		$a_81_7 = {73 74 61 72 74 65 72 } //00 00  starter
	condition:
		any of ($a_*)
 
}