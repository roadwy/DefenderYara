
rule TrojanDownloader_BAT_AgentTesla_EQQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.EQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 93 28 90 01 05 59 0c 20 ff ff 00 00 08 2f 0a 08 20 ff ff 00 00 59 0c 2b 0c 16 08 31 08 08 20 ff ff 00 00 58 0c 06 07 08 d1 9d 07 17 58 0b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}