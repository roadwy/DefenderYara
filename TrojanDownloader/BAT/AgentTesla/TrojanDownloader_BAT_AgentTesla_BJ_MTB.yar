
rule TrojanDownloader_BAT_AgentTesla_BJ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 00 38 00 35 00 2e 00 32 00 33 00 32 00 2e 00 31 00 36 00 36 00 2e 00 31 00 30 00 2f 00 61 00 73 00 73 00 65 00 74 00 73 00 } //02 00  185.232.166.10/assets
		$a_01_1 = {59 00 6f 00 7a 00 72 00 66 00 75 00 74 00 6e 00 6a 00 } //02 00  Yozrfutnj
		$a_01_2 = {24 63 61 62 38 64 31 62 63 2d 39 62 33 37 2d 34 36 34 30 2d 38 37 61 34 2d 30 65 33 30 64 66 32 39 37 39 31 39 } //01 00  $cab8d1bc-9b37-4640-87a4-0e30df297919
		$a_01_3 = {52 65 61 64 42 79 74 65 73 } //01 00  ReadBytes
		$a_01_4 = {47 65 74 42 79 74 65 73 } //00 00  GetBytes
	condition:
		any of ($a_*)
 
}