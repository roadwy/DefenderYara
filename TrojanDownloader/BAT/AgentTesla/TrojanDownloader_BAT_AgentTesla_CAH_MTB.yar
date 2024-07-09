
rule TrojanDownloader_BAT_AgentTesla_CAH_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.CAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 72 ?? 00 00 70 7e ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0b de 03 26 de cf 07 2a } //2
		$a_01_1 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}