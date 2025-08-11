
rule TrojanDownloader_BAT_AgentTesla_PMZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.PMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 3a 1a 00 00 00 73 04 00 00 0a 72 01 00 00 70 73 05 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 06 39 0a 00 00 00 06 16 06 8e 69 28 ?? 00 00 0a dd 13 00 00 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}