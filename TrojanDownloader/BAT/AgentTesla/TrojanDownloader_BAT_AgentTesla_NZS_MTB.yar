
rule TrojanDownloader_BAT_AgentTesla_NZS_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.NZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {73 00 73 00 6f 00 6f 00 31 00 34 00 35 00 31 00 2e 00 64 00 64 00 6e 00 73 00 2e 00 6e 00 65 00 74 00 3a 00 31 00 34 00 35 00 33 00 2f 00 90 02 18 2e 00 70 00 6e 00 67 00 90 00 } //01 00 
		$a_03_1 = {73 73 6f 6f 31 34 35 31 2e 64 64 6e 73 2e 6e 65 74 3a 31 34 35 33 2f 90 02 18 2e 70 6e 67 90 00 } //01 00 
		$a_81_2 = {75 36 6e 48 47 69 77 68 48 59 32 6a 4d 43 4a 6d 67 73 2e 46 74 4d 6b 57 6c 6e 61 46 61 72 67 42 4e 44 37 6d 76 } //00 00  u6nHGiwhHY2jMCJmgs.FtMkWlnaFargBND7mv
	condition:
		any of ($a_*)
 
}