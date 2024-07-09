
rule TrojanDownloader_BAT_AgentTesla_ABOI_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABOI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {04 8e 69 5d 91 02 07 91 61 d2 6f ?? ?? ?? 0a 07 17 58 0b 07 02 8e 69 32 dc 06 6f ?? ?? ?? 0a 25 2d 02 26 14 2a 90 0a 30 00 06 7e ?? ?? ?? 04 07 7e } //5
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {47 65 74 54 79 70 65 73 } //1 GetTypes
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}