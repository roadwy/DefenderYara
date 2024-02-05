
rule TrojanDownloader_BAT_AgentTesla_STB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.STB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 00 6d 00 6c 00 2f 00 6c 00 69 00 76 00 65 00 72 00 70 00 6f 00 6f 00 6c 00 2d 00 66 00 63 00 2d 00 6e 00 65 00 77 00 73 00 2f 00 66 00 65 00 61 00 74 00 75 00 72 00 65 00 73 00 2f 00 73 00 74 00 65 00 76 00 65 00 6e 00 2d 00 67 00 65 00 72 00 72 00 61 00 72 00 64 00 } //00 00 
	condition:
		any of ($a_*)
 
}