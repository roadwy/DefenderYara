
rule TrojanDownloader_BAT_AgentTesla_HWMF_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.HWMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 16 00 00 00 12 00 28 ?? ?? ?? 06 38 1a 00 00 00 38 12 00 00 00 38 0d 00 00 00 00 28 ?? ?? ?? 06 13 00 38 dd ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}