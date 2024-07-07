
rule TrojanDownloader_BAT_AgentTesla_KAA_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 13 06 16 13 07 11 06 12 07 28 90 01 01 00 00 0a 00 08 07 11 05 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 de 0d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}