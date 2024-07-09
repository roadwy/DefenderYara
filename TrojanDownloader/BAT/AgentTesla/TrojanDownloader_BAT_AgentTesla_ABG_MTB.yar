
rule TrojanDownloader_BAT_AgentTesla_ABG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 03 0c 2b 00 07 16 73 03 ?? ?? 0a 73 04 ?? ?? 0a 0d 09 08 6f 05 ?? ?? 0a de 07 09 6f 06 ?? ?? 0a dc 08 6f 07 ?? ?? 0a 13 04 de 0e 90 0a 55 00 72 01 ?? ?? 70 28 02 ?? ?? 06 18 2d 0d 26 06 73 01 ?? ?? 0a 18 2d 06 26 2b 06 0a 2b f1 0b 2b 00 73 02 ?? ?? 0a 1b 2d 03 26 } //5
		$a_01_1 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_2 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}