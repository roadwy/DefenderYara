
rule TrojanDownloader_BAT_AgentTesla_CAG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.CAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 66 00 72 90 01 01 00 00 70 28 90 01 01 00 00 06 73 90 01 01 00 00 0a 0b 73 90 01 01 00 00 0a 0c 07 16 73 90 01 01 00 00 0a 73 90 01 01 00 00 0a 0d 09 08 6f 90 01 01 00 00 0a de 0a 90 00 } //02 00 
		$a_03_1 = {07 2c 06 07 6f 90 01 01 00 00 0a dc 26 20 e0 2e 00 00 28 90 01 01 00 00 0a de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}