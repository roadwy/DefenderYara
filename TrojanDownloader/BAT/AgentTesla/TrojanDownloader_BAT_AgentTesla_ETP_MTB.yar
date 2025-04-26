
rule TrojanDownloader_BAT_AgentTesla_ETP_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ETP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 09 02 09 91 6f ?? ?? ?? 0a 2b 07 28 ?? ?? ?? 0a 2b ec } //1
		$a_03_1 = {09 25 17 59 0d 16 fe 02 13 06 11 06 2d bd 28 ?? ?? ?? 0a 13 07 12 07 23 00 00 00 00 00 00 33 40 28 ?? ?? ?? 0a 0c 2b 02 } //1
		$a_01_2 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c 54 79 70 65 } //1 SecurityProtocolType
		$a_01_3 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}