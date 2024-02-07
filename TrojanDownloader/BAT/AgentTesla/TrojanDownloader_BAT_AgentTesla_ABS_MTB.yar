
rule TrojanDownloader_BAT_AgentTesla_ABS_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 14 02 00 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 10 00 00 00 03 00 00 00 03 00 00 00 04 00 00 00 16 00 00 00 } //01 00 
		$a_01_1 = {47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 72 67 73 } //01 00  GetCommandLineArgs
		$a_01_2 = {73 69 6d 70 6c 65 64 6f 77 6e 6c 6f 61 64 65 72 } //01 00  simpledownloader
		$a_01_3 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 } //01 00  Downloading
		$a_01_4 = {43 00 68 00 65 00 63 00 6b 00 20 00 69 00 66 00 20 00 74 00 68 00 65 00 20 00 69 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 61 00 64 00 64 00 72 00 65 00 73 00 73 00 20 00 69 00 73 00 20 00 76 00 61 00 6c 00 69 00 64 00 } //00 00  Check if the internet address is valid
	condition:
		any of ($a_*)
 
}