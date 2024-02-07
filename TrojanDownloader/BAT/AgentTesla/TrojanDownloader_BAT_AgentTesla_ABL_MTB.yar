
rule TrojanDownloader_BAT_AgentTesla_ABL_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 08 00 "
		
	strings :
		$a_03_0 = {06 0a 2b 07 28 90 01 03 06 2b eb 06 16 06 8e 69 28 90 01 03 0a 2b 07 90 0a 21 00 02 72 90 01 03 70 28 06 90 00 } //01 00 
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_01_2 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_BAT_AgentTesla_ABL_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 06 6f 2a 90 01 02 0a 0d 07 09 6f 90 01 03 0a 07 18 6f 90 01 03 0a 02 13 04 07 6f 90 01 03 0a 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 dd 90 01 03 00 08 39 90 01 03 00 08 6f 90 01 03 0a dc 90 00 } //05 00 
		$a_03_1 = {07 09 16 11 04 6f 90 01 03 0a 08 09 16 09 8e 69 6f 90 01 03 0a 25 13 04 16 3d 90 01 03 ff 07 6f 90 01 03 0a 13 05 90 00 } //01 00 
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //01 00  CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}