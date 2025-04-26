
rule TrojanDownloader_BAT_AgentTesla_CAG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.CAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0a 2b 66 00 72 ?? 00 00 70 28 ?? 00 00 06 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 07 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a de 0a } //2
		$a_03_1 = {07 2c 06 07 6f ?? 00 00 0a dc 26 20 e0 2e 00 00 28 ?? 00 00 0a de } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}