
rule TrojanDownloader_BAT_AgentTesla_KAB_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 02 28 ?? ?? ?? 06 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 90 0a 26 00 72 ?? ?? ?? 70 0a 73 } //1
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}