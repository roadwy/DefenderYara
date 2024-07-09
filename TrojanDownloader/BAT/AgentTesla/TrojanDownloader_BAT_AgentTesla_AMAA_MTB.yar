
rule TrojanDownloader_BAT_AgentTesla_AMAA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 20 97 59 c0 e0 28 ?? 01 00 06 28 ?? 01 00 0a 6f ?? 01 00 0a 06 20 ?? ?? ?? e0 28 ?? 01 00 06 28 ?? 01 00 0a 6f ?? 01 00 0a 06 06 6f ?? 01 00 0a 06 6f ?? 01 00 0a 6f ?? 01 00 0a 13 05 73 ?? 00 00 0a 0c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}