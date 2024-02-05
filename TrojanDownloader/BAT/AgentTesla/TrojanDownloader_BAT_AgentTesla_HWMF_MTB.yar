
rule TrojanDownloader_BAT_AgentTesla_HWMF_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.HWMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {38 16 00 00 00 12 00 28 90 01 03 06 38 1a 00 00 00 38 12 00 00 00 38 0d 00 00 00 00 28 90 01 03 06 13 00 38 dd ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}