
rule TrojanDownloader_BAT_AgentTesla_ERX_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ERX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 13 05 2b 10 00 1c 2c cf 06 08 11 05 91 6f 90 01 03 0a 00 00 11 05 25 17 59 13 05 16 25 2d fa fe 02 13 06 11 06 2d dd 06 6f 90 01 03 0a 0c 08 13 07 2b 00 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_2 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}