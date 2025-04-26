
rule TrojanDownloader_BAT_AgentTesla_ABZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 1a 2d 15 2b 0d 06 16 06 8e 69 1c 2d 0e 26 26 26 2b 03 26 2b f0 06 2b 0a 0a 2b ea 28 ?? ?? ?? 0a 2b f3 2a 90 0a 2d 00 72 01 ?? ?? 70 28 02 } //5
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}