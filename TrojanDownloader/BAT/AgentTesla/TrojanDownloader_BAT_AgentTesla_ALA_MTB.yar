
rule TrojanDownloader_BAT_AgentTesla_ALA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ALA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 18 5b 8d 2b 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 33 00 00 0a 1f 10 28 34 00 00 0a 9c 08 18 58 0c 08 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}