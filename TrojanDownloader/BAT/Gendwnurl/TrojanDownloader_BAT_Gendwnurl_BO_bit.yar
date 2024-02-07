
rule TrojanDownloader_BAT_Gendwnurl_BO_bit{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.BO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 00 74 00 74 00 70 00 3a 00 90 02 20 2e 00 70 00 77 00 2f 00 69 00 70 00 32 00 2e 00 70 00 68 00 70 00 3f 00 65 00 78 00 3d 00 90 00 } //01 00 
		$a_01_1 = {53 00 74 00 65 00 61 00 6d 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00 } //01 00  SteamService.exe
		$a_01_2 = {39 00 32 00 33 00 66 00 33 00 32 00 39 00 79 00 66 00 39 00 } //00 00  923f329yf9
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_Gendwnurl_BO_bit_2{
	meta:
		description = "TrojanDownloader:BAT/Gendwnurl.BO!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 45 00 58 00 20 00 28 00 4e 00 65 00 77 00 2d 00 4f 00 62 00 6a 00 65 00 63 00 74 00 20 00 4e 00 65 00 74 00 2e 00 57 00 65 00 62 00 43 00 6c 00 69 00 65 00 6e 00 74 00 29 00 2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 68 00 74 00 74 00 70 00 } //01 00  IEX (New-Object Net.WebClient).DownloadString('http
		$a_01_1 = {2e 00 6a 00 70 00 67 00 27 00 29 00 3b 00 20 00 68 00 61 00 63 00 6b 00 62 00 61 00 63 00 6b 00 74 00 72 00 61 00 63 00 6b 00 } //00 00  .jpg'); hackbacktrack
	condition:
		any of ($a_*)
 
}