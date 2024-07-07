
rule TrojanDownloader_BAT_AgentTesla_MPA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.MPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {1e 2c 0d 17 2c 0a 1d 2c 07 2c 04 1e 2c ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}