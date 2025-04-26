
rule TrojanDownloader_BAT_AgentTesla_ESG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ESG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_03_0 = {0d 12 03 28 ?? ?? ?? 0a 23 00 00 00 00 00 00 34 40 fe 04 0c 08 90 09 08 00 00 00 06 6f ?? ?? ?? 0a } //10
		$a_03_1 = {0c 12 02 28 ?? ?? ?? 0a 1f 14 fe 04 0b 07 90 09 08 00 00 00 06 6f ?? ?? ?? 0a } //10
		$a_03_2 = {06 07 03 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe 02 0c 08 } //1
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=13
 
}