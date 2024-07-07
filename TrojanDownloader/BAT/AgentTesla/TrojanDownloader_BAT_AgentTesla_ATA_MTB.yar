
rule TrojanDownloader_BAT_AgentTesla_ATA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ATA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 16 0b 2b 19 06 03 07 18 6f 08 00 00 0a 1f 10 28 09 00 00 0a 6f 0a 00 00 0a 07 18 58 0b 07 03 6f 0b 00 00 0a 32 de } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}