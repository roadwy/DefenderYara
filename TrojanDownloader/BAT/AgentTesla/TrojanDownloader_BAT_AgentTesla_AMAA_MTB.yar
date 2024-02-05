
rule TrojanDownloader_BAT_AgentTesla_AMAA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 20 97 59 c0 e0 28 90 01 01 01 00 06 28 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 06 20 90 01 03 e0 28 90 01 01 01 00 06 28 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 06 06 6f 90 01 01 01 00 0a 06 6f 90 01 01 01 00 0a 6f 90 01 01 01 00 0a 13 05 73 90 01 01 00 00 0a 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}