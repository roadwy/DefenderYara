
rule TrojanDownloader_BAT_AgentTesla_ESV_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ESV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 07 03 07 91 2b 18 00 2b 0b 07 25 17 59 0b 16 fe 02 0c 2b 03 00 2b f2 08 2d 02 2b 09 2b e0 } //01 00 
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}