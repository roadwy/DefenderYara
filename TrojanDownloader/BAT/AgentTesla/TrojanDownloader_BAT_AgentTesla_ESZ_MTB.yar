
rule TrojanDownloader_BAT_AgentTesla_ESZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ESZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 2c 02 2b 09 2b 0a 13 06 38 ?? ?? ?? ?? 17 2b 03 16 2b 00 2d ?? 06 6f ?? ?? ?? 0a 0d 2b 00 09 2a } //1
		$a_01_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}