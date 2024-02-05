
rule TrojanDownloader_BAT_AgentTesla_MPB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.MPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {09 11 04 08 11 04 08 8e 69 5d 91 06 11 04 91 61 d2 9c 11 04 17 58 13 04 11 04 06 8e 69 32 e1 } //00 00 
	condition:
		any of ($a_*)
 
}