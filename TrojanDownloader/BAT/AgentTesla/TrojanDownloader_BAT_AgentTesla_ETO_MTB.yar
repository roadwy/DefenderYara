
rule TrojanDownloader_BAT_AgentTesla_ETO_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ETO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 13 04 16 13 05 11 04 12 05 28 ?? ?? ?? 0a 00 07 09 02 09 91 6f ?? ?? ?? 0a 00 de 0d 11 05 2c 08 11 04 28 ?? ?? ?? 0a 00 dc 00 09 25 17 59 0d 16 } //10
		$a_01_1 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //1 SecurityProtocolType
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}