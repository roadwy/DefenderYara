
rule TrojanDownloader_BAT_AgentTesla_ABR_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 5f 50 61 73 73 77 6f 72 64 } //01 00  set_Password
		$a_01_1 = {5a 69 70 46 69 6c 65 } //01 00  ZipFile
		$a_01_2 = {47 65 74 54 65 6d 70 50 61 74 68 } //01 00  GetTempPath
		$a_01_3 = {77 00 33 00 29 00 4a 00 68 00 62 00 32 00 69 00 55 00 34 00 3c 00 4e 00 4c 00 73 00 5f 00 50 00 } //01 00  w3)Jhb2iU4<NLs_P
		$a_01_4 = {57 00 57 00 70 00 4f 00 51 00 30 00 31 00 48 00 52 00 6c 00 68 00 50 00 57 00 46 00 5a 00 71 00 54 00 58 00 70 00 46 00 64 00 31 00 70 00 56 00 61 00 46 00 4a 00 51 00 55 00 54 00 30 00 39 00 } //01 00  WWpOQ01HRlhPWFZqTXpFd1pVaFJQUT09
		$a_01_5 = {24 66 65 64 62 65 31 64 30 2d 63 36 33 30 2d 34 65 35 35 2d 39 35 33 39 2d 39 61 37 66 30 66 61 37 66 37 38 38 } //00 00  $fedbe1d0-c630-4e55-9539-9a7f0fa7f788
	condition:
		any of ($a_*)
 
}