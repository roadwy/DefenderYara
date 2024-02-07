
rule TrojanDownloader_BAT_AgentTesla_EOT_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.EOT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 02 07 91 6f 90 01 03 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 2d e8 90 00 } //01 00 
		$a_03_1 = {09 11 04 16 11 04 8e 69 6f 90 01 03 0a 13 05 07 11 04 16 11 05 6f 90 01 03 0a 00 00 11 05 16 fe 02 13 06 11 06 2d d8 90 00 } //01 00 
		$a_01_2 = {2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 31 00 35 00 } //00 00  /c timeout 15
	condition:
		any of ($a_*)
 
}