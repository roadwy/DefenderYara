
rule Trojan_BAT_AgentTesla_MW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 ff a2 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9b 00 00 00 72 00 00 00 79 02 00 00 c5 04 00 00 7c } //01 00 
		$a_01_1 = {65 6d 62 65 64 64 65 72 5f 64 6f 77 6e 6c 6f 61 64 5f 64 61 74 61 } //01 00  embedder_download_data
		$a_01_2 = {74 69 6d 65 50 61 73 73 77 6f 72 64 43 68 61 6e 67 65 64 } //01 00  timePasswordChanged
		$a_01_3 = {43 6f 6f 6b 69 65 73 4e 6f 74 46 6f 75 6e 64 } //01 00  CookiesNotFound
		$a_01_4 = {65 6e 63 72 79 70 74 65 64 50 61 73 73 77 6f 72 64 } //01 00  encryptedPassword
		$a_01_5 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //01 00  DownloadFile
		$a_01_6 = {73 65 74 5f 55 73 65 5a 69 70 36 34 57 68 65 6e 53 61 76 69 6e 67 } //00 00  set_UseZip64WhenSaving
	condition:
		any of ($a_*)
 
}