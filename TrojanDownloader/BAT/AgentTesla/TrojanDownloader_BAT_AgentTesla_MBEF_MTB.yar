
rule TrojanDownloader_BAT_AgentTesla_MBEF_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.MBEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 00 37 00 32 00 2e 00 32 00 34 00 35 00 2e 00 31 00 39 00 31 00 2e 00 31 00 37 00 2f 00 30 00 30 00 30 00 2f } //00 00 
	condition:
		any of ($a_*)
 
}